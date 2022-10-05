# stdlib
from collections import defaultdict
from string import Template
import pdb

# 3p
from elasticsearch.client import IndicesClient
from elasticsearch.client.ingest import IngestClient
from elasticsearch.helpers import bulk
from elasticsearch_dsl import Q, A, Search, UpdateByQuery
from elasticsearch_dsl.connections import get_connection

# proj
from enums import QueryEnum, TagEnum
from persistence.doc_service_ip import get_ip_idx_doc, get_placebo_ip_idx_doc
import utils


###############################################################################
# CONSTANTS

CONFIG = utils.get_config()
LOGGER = utils.get_logger("es_utils")
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in NONPLACEBOS]
TIME_WINDOWS = CONFIG["TIME"]["WINDOWS"]
TIME_FMT = CONFIG["TIME"]["FMT"]

INDICES_IP_MAPPING = {
    "nginx-access-*": "ip.keyword",
    "postfix-*": "postfix_client_ip.keyword",
    "telnet-*": "ip.keyword",
    "ftp-*": "ip.keyword",
    "ssh-*": "ssh.ip.keyword",
    "fp-*": "fp.clientIP.geobytesipaddress.keyword",
}

BOT_TAGS_FIELD = "bot_filter_tags"
USER_TAGS_FIELD = "user_filter_tags"
OTHER_TAGS_FIELD = "other_tags"

GEOIP_PIPELINE_ID = "geoip"
NON_BOT_IDX_PREFIX = "nonbot"
CONST_LOG_EVERY_N = 100_000
BATCH_SIZE = 1024
LOG_PROGRESS = {"nginx-access-*": 100_000, "ftp-*": 1_000, "telnet-*": 10_000, "ssh-*": 10_000}

SCRIPT_ADD_FILTER_TAG = Template(
    """ if (ctx._source.containsKey("$field")) {
if (!ctx._source.$field.contains(params.tag)) {
    ctx._source.$field.add(params.tag);
}
} else {
    ctx._source.$field = [params.tag];
}
"""
)
SCRIPT_REMOVE_FILTER_TAG = Template(
    """ 
if (ctx._source.containsKey("$field")) {
    if (ctx._source.$field.contains(params.tag)) {
        ctx._source.$field.remove(ctx._source.$field.indexOf(params.tag));
    }
}
"""
)
SCRIPT_REINDEX_REMOVE_FILTER_TAGS = """ 
    ctx._id = ctx._source.ip;
    ctx._source.remove(\"filter_tags\");
"""


###############################################################################


def get_ip_field(idx_ptrn):
    return INDICES_IP_MAPPING[idx_ptrn]


# def get_ip_index(idx_ptrn):
#     srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
#     new_idx = f"ips-{srvc}"
#     return new_idx


def get_geoip_index(idx_ptrn, placebo=False):
    ip_doc_class = get_ip_idx_doc(idx_ptrn) if not placebo else get_placebo_ip_idx_doc(idx_ptrn)
    return ip_doc_class._index._name


def get_tag_script(tag_type, add=True):
    template = SCRIPT_ADD_FILTER_TAG if add else SCRIPT_REMOVE_FILTER_TAG
    if tag_type == TagEnum.BOT:
        return template.substitute(field=BOT_TAGS_FIELD)
    elif tag_type == TagEnum.USER:
        return template.substitute(field=USER_TAGS_FIELD)
    elif tag_type == TagEnum.OTHER:
        return template.substitute(field=OTHER_TAGS_FIELD)
    else:
        raise RuntimeError(f"Unknown TagEnum value: {tag_type}")


###############################################################################
# TOKENIZATION/ANALYSIS
def get_num_tokens(text, analyzer="standard"):
    indices_client = IndicesClient(get_connection())
    res = indices_client.analyze(body={"analyzer": analyzer, "text": text})
    return len(res["tokens"])


###############################################################################
# IP TAG STATUS


def ip_tagged_bot(hit):
    return BOT_TAGS_FIELD in hit and len(hit.bot_filter_tags) > 0


def ip_tagged_user(hit):
    return USER_TAGS_FIELD in hit and len(hit.user_filter_tags) > 0


def ip_untagged(hit):
    return not (ip_tagged_bot(hit) or ip_tagged_user(hit))


def ip_non_bot(hit):
    return ip_tagged_user(hit) or ip_untagged(hit)


def ip_tagged_both(hit):
    return ip_tagged_bot(hit) and ip_tagged_user(hit)


def get_status_ips(idx_ptrn, is_status_func):
    ip_idx = get_geoip_index(idx_ptrn)
    search = init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
    search = search.params(size=BATCH_SIZE)
    LOGGER.info(f"  get_status_ips {idx_ptrn} {is_status_func.__name__}")
    for idx, hit in enumerate(search.scan()):
        if idx % LOG_PROGRESS[idx_ptrn] == 0:
            LOGGER.debug(f"    on ip {idx}...")
        if is_status_func(hit):
            yield hit.ip


###############################################################################


def scan_aggs(search, source_aggs, inner_aggs={}, size=1_000):
    """
    Helper function used to iterate over all possible bucket combinations of
    ``source_aggs``, returning results of ``inner_aggs`` for each. Uses the
    ``composite`` aggregation under the hood to perform this.
    """

    def run_search(**kwargs):
        s = search[:0]
        s.aggs.bucket("comp", "composite", sources=source_aggs, size=size, **kwargs)
        for agg_name, agg in inner_aggs.items():
            s.aggs["comp"][agg_name] = agg
        return s.execute()

    response = run_search()
    while response.aggregations.comp.buckets:
        for b in response.aggregations.comp.buckets:
            yield b
        if "after_key" in response.aggregations.comp:
            after = response.aggregations.comp.after_key
        else:
            after = response.aggregations.comp.buckets[-1].key
        response = run_search(after=after)


def init_query(query_type, idx_ptrn, filter_time=True, ctids=None, sort_timestamp=False):
    q = None
    if query_type == QueryEnum.SEARCH:
        q = Search(index=idx_ptrn)
    elif query_type == QueryEnum.UBQ:
        q = UpdateByQuery(index=idx_ptrn)
    else:
        raise RuntimeError(f"Unknown query type {query_type}.")
    if filter_time:
        start_window = TIME_WINDOWS["START"]
        end_window = TIME_WINDOWS["END"]
        q = q.filter(
            "range",
            **{"@timestamp": {"gte": start_window, "lt": end_window, "format": TIME_FMT}},
        )
    if ctids is not None:
        q = q.filter(
            "terms_set",
            log__container={"terms": ctids, "minimum_should_match_script": {"source": "1"}},
        )
    if sort_timestamp:
        q = q.sort({"log.container.keyword": {"order": "asc"}}, {"@timestamp": {"order": "asc"}})
    return q


###############################################################################


def get_num_ips(idx_ptrn, ctids):
    search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids)
    search.aggs.metric("num_ips", "cardinality", field=get_ip_field(idx_ptrn))
    res = search.execute()
    return res.aggs.num_ips.value


def get_ips(idx_ptrn, search=None, filter_time=False, tag=None, ctids=None, with_agg=True):
    """Return all client IPs from the index pattern.

    Parameters
    ----------
    idx_ptrn : string
    filter_time : bool
        filter for config time window if set
    tag : string
        filter for this tag if set
    ctids : list(str)
        filter for these ctids if set

    Returns
    -------
    ips : generator
        buckets of unique IPs from scan_aggs or IP documents
    """
    if with_agg:
        ip_agg = {"ip": A("terms", field=get_ip_field(idx_ptrn))}
        if search is None:
            search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=filter_time, ctids=ctids)
        if tag is not None:
            search = search.query(
                "terms_set",
                filter_tag={"terms": tag, "minimum_should_match_script": {"source": "1"}},
            )
        # LOGGER.debug(f"get_ips search {search.to_dict()}")
        _generator = scan_aggs(search, [ip_agg], size=1_000)
    else:
        ip_idx = get_geoip_index(idx_ptrn)
        if search is None:
            search = init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
            search = search.params(size=1_000)
        _generator = search.scan()
    return _generator


def batch_ips_from_buckets(ip_generator, n=1):
    return utils.batch_iterable(ip_generator, n=n, key=lambda b: b.key.ip)
    # batch = []
    # for bucket in ip_generator:
    #     if len(batch) == n:
    #         yield batch
    #         batch = []
    #     batch.append(bucket.key.ip)
    # if len(batch) > 0:
    #     yield batch
    # return set(bucket.key.ip for bucket in ip_generator)


# def tag_all_ips(idx_ptrn, tag, _generator):
#     nonplacebos = sorted(list(NONPLACEBOS.keys()))
#     nonplacebos = [str(_id) for _id in nonplacebos]
#     LOGGER.debug(f"tag_all_ips {idx_ptrn} {tag}...")
#     num_ips_found = 0
#     for idx, bucket in enumerate(_generator):
#         if idx % CONST_LOG_EVERY_N == 0:
#             LOGGER.debug(f"  at bucket {idx}...")
#         ip = bucket.key.ip
#         ubq = init_query(QueryEnum.UBQ, idx_ptrn, filter_time=True, ctids=nonplacebos)
#         ubq = ubq.query("term", ip=ip)  # query only for the ip
#         ubq = ubq.extra(explain=True)
#         ubq = ubq.script(source="ctx._source.filter_tag = params.tag", params={"tag": tag})
#         response = ubq.execute()
#         if len(response.failures) > 0:
#             LOGGER.debug(f"  UBQ failed. {response.to_dict()}")
#         if response.updated > 0:
#             num_ips_found += 1
#         # if not response.success():
#         #     LOGGER.debug(f"  UBQ failed. {response.to_dict()}")
#     LOGGER.info(f"> tagged nonplacebo {num_ips_found} IPs with {tag}")


###############################################################################
# CREATING & TAGGIING IPS


def create_ip_index(idx_ptrn, placebo=False, ip_doc_class=None):
    create_geoip_pipeline()  # ensure it's created
    if ip_doc_class is None:
        ip_doc_class = get_ip_idx_doc(idx_ptrn) if not placebo else get_placebo_ip_idx_doc(idx_ptrn)
    ip_doc_class.init()
    index = ip_doc_class._index._name
    LOGGER.info(f"create_ip_index {idx_ptrn} -> {index}")
    return index, ip_doc_class


def _generate_ip_entries(ip_doc_class, ips, bot_filter_tags=[], user_filter_tags=[]):
    LOGGER.debug(f"_generate_ip_entries for {ip_doc_class._index._name}")
    for idx, ip in enumerate(ips):
        if idx % 100_000 == 0:
            LOGGER.debug(f"  on ip num {idx}...")
        if not utils.validate_ip(ip):
            continue
        doc = ip_doc_class(
            ip=ip, bot_filter_tags=bot_filter_tags, user_filter_tags=user_filter_tags
        )
        doc.meta.id = ip
        d = doc.to_dict(include_meta=True)
        d["pipeline"] = GEOIP_PIPELINE_ID
        yield d
        # entry = dict(_id=ip, _index=index, _source={"ip": ip, FILTER_TAGS_FIELD: tags})
        # yield entry


def _update_ip_entries(index, ips, tag, tag_type):
    def _get_should(ips):
        filtered = [ip for ip in ips if utils.validate_ip(ip)]
        return [Q("term", ip=ip) for ip in filtered]

    ubq = init_query(QueryEnum.UBQ, index, filter_time=False, ctids=None, sort_timestamp=False)
    query = Q(
        "bool",
        must=[],
        must_not=[],
        should=_get_should(ips),
        minimum_should_match=1,
    )
    ubq = ubq.query(query)
    ubq = ubq.script(
        source=get_tag_script(tag_type=tag_type),
        params={"tag": tag},
    )
    ubq = ubq.params(conflicts="proceed")
    response = ubq.execute()
    # LOGGER.debug(f"_update_ip_entries {response.to_dict()}")
    return response.updated


# def _update_ip_entries(index, ips, tag, bot=True):
#     def _yield_actions(ips):
#         for ip in ips:
#             yield {
#                 "_op_type": "update",
#                 "_index": index,
#                 "_id": ip,
#                 "script": {"source": get_add_tag_script(bot=bot), "params": {"tag": tag}},
#             }

#     response = bulk(
#         get_connection(),
#         _yield_actions(ips),
#         max_retries=CONFIG["ELASTICSEARCH"]["MAX_RETRIES"],
#         stats_only=True,
#     )
#     LOGGER.debug(f"> response {response}")
#     return 0


def init_ip_index(idx_ptrn, placebo=False):
    def _get_ips_from_buckets(ips_gen):
        for bucket in ips_gen:
            yield bucket.key.ip

    # pdb.set_trace()
    ctids = PLACEBOS if placebo else NONPLACEBOS
    ctids = sorted(list(ctids.keys()))
    ctids = [str(_id) for _id in ctids]
    ips_gen = get_ips(idx_ptrn, filter_time=True, tag=None, ctids=ctids)

    # ip_index = get_ip_index(idx_ptrn)
    _, ip_doc_class = create_ip_index(idx_ptrn, placebo=placebo)
    unique_ips = _get_ips_from_buckets(ips_gen)

    LOGGER.debug(f"init_ip_index {idx_ptrn} {ip_doc_class._index_.name}...")
    response = bulk(
        get_connection(),
        _generate_ip_entries(ip_doc_class, unique_ips),
        max_retries=CONFIG["ELASTICSEARCH"]["MAX_RETRIES"],
        raise_on_error=False,
        raise_on_exception=False,
    )
    LOGGER.debug(f"> response {response}")


# def init_ip_index_w_gen(ip_doc_class, ips_gen):
#     ip_doc_class.init()
#     LOGGER.debug(f"init_ip_index {ip_doc_class._index._name}...")
#     response = bulk(
#         get_connection(),
#         _generate_ip_entries(ip_doc_class, ips_gen),
#         max_retries=CONFIG["ELASTICSEARCH"]["MAX_RETRIES"],
#         raise_on_error=False,
#         raise_on_exception=False,
#     )
#     LOGGER.debug(f"> response {response}")


def tag_ips(idx_ptrn, ips_gen, tag, tag_type=TagEnum.BOT, bucketed=True, placebo=False):
    # pdb.set_trace()
    ip_index = get_geoip_index(idx_ptrn, placebo=placebo)
    if bucketed:
        ips = batch_ips_from_buckets(ips_gen, n=BATCH_SIZE)
    else:
        ips = utils.batch_iterable(ips_gen, n=BATCH_SIZE)
    LOGGER.info(f"  tag_ips for {tag} batch_size={BATCH_SIZE}")
    num_ips = 0
    for idx, batch in enumerate(ips):
        if idx % 10 == 0:
            LOGGER.debug(f"    at batch {idx}...")
        batch_ips = _update_ip_entries(ip_index, batch, tag, tag_type=tag_type)
        num_ips += batch_ips
    LOGGER.info(f"  tagged {num_ips} IPs with {tag}")


###############################################################################
# SANKEY HELPERS

# def get_ctids_contacted(idx_ptrn, ip):
#     search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True)
#     ip_query = Q("term", **{get_ip_field(idx_ptrn): ip})
#     search = search.query(ip_query)


# TOO SLOW
# def get_unique_ctid_ips(idx_ptrn, ctid):
#     num_unique = 0
#     LOGGER.info(f"  get_unique_ctid_ips {idx_ptrn} {ctid}")
#     for idx, ip in enumerate(get_ips(idx_ptrn, filter_time=True, ctids=[ctid])):
#         if idx % LOG_PROGRESS[idx_ptrn] == 0:
#             LOGGER.debug(f"  on ip {idx}...")
#         search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True)
#         search.aggs.metric("num_ctids", "cardinality", field="log.container.keyword")
#         res = search.execute()
#         if res.aggs.num_ctids.value == 1:
#             num_unique += 1
#             yield ip
#     LOGGER.info(f"  get_unique_ctid_ips {idx_ptrn} {ctid}: {num_unique}")


# def get_ip_tag_group(idx_ptrn, ip, bot_grouping, user_grouping):
#     ip_idx = get_geoip_index(idx_ptrn)
#     search = init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
#     ip_query = Q("term", **{get_ip_field(idx_ptrn): ip})
#     search = search.query(ip_query)
#     for hit in search.scan():
#         tag_status = TagEnum.UNTAGGED
#         field = None
#         grouping = None
#         if ip_tagged_bot(hit):
#             field = BOT_TAGS_FIELD
#             tag_status = TagEnum.BOT
#             grouping = bot_grouping
#         elif ip_tagged_user(hit):
#             field = USER_TAGS_FIELD
#             tag_status = TagEnum.USER
#             grouping = user_grouping
#         if grouping is not None:
#             for (tag_group, tags) in grouping.items():
#                 if len(set(tags).intersection(set(hit[field]))) > 0:
#                     return tag_status, tag_group
#     return None, None


###############################################################################
# IP TAG STATUS


def _determine_tags(ip_idx, ips):
    search = init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
    validated_ips = [ip for ip in ips if utils.validate_ip(ip)]
    query = Q(
        "bool",
        must=[],
        must_not=[],
        should=[Q("term", ip=ip) for ip in validated_ips],
        minimum_should_match=1,
    )
    search = search.query(query)
    res = defaultdict(int)
    num_bot_tags = defaultdict(int)
    num_user_tags = defaultdict(int)
    for hit in search.scan():
        if ip_untagged(hit):
            res["untagged"] += 1
        elif ip_tagged_both(hit):
            res["both"] += 1
        else:
            _type = "user"
            _key = USER_TAGS_FIELD
            _stats = num_user_tags
            if ip_tagged_bot(hit):
                _type = "bot"
                _key = BOT_TAGS_FIELD
                _stats = num_bot_tags
            res[_type] += 1
            tags = hit[_key]
            for tag in tags:
                _stats[tag] += 1
    return res, num_bot_tags, num_user_tags


def get_tagged_ips(idx_ptrn, ips_gen):
    def _update_stats_dicts(overall, batch):
        assert len(overall) == len(batch)
        for i in range(len(overall)):
            overall_i = overall[i]
            batch_i = batch[i]
            for key in batch_i:
                overall_i[key] += batch_i[key]

    ip_index = get_geoip_index(idx_ptrn)
    ips = batch_ips_from_buckets(ips_gen, n=BATCH_SIZE)
    stats = defaultdict(int)
    num_bot_tags = defaultdict(int)
    num_user_tags = defaultdict(int)
    overall = [stats, num_bot_tags, num_user_tags]
    LOGGER.info(f"  get_tagged_ips for {idx_ptrn}...")
    for idx, batch in enumerate(ips):
        if idx % 10 == 0:
            LOGGER.info(f"    at ip {idx*BATCH_SIZE}...")
        batch_stats = _determine_tags(ip_index, batch)
        _update_stats_dicts(overall, batch_stats)
    num_ips = sum(stats.values())
    LOGGER.info(f"  found {num_ips} IPs {stats}")
    return stats, num_bot_tags, num_user_tags


def get_ip_status(idx_ptrn):
    ips_gen = get_ips(idx_ptrn, with_agg=False)
    ip_status = defaultdict(str)
    ip_tags = defaultdict(lambda: defaultdict(list))
    LOGGER.info(f"get_ip_status {idx_ptrn}")
    for idx, hit in enumerate(ips_gen):
        if idx % LOG_PROGRESS[idx_ptrn] == 0:
            LOGGER.debug(f"  on ip {idx}...")
        ip = hit.ip
        status = "untagged"
        has_user = False
        has_bot = False
        if ip_tagged_both(hit):
            status = "both"
            has_user = True
            has_bot = True
        elif ip_tagged_bot(hit):
            status = "bot"
            has_bot = True
        elif ip_tagged_user(hit):
            status = "user"
            has_user = True
        ip_status[ip] = status
        if has_user:
            ip_tags[ip][USER_TAGS_FIELD] = hit[USER_TAGS_FIELD]
        if has_bot:
            ip_tags[ip][BOT_TAGS_FIELD] = hit[BOT_TAGS_FIELD]
    return ip_status, ip_tags


def get_tagged_ips_ctr(idx_ptrn, ip_status, ip_tags, ctr):
    def _update_ip_stats(ip, status, ip_tags, stats, num_bot_tags, num_user_tags):
        tags = []
        num_type_tags = None
        stats[status] += 1
        if status == "bot":
            tags = ip_tags[ip][BOT_TAGS_FIELD]
            num_type_tags = num_bot_tags
        if status == "user":
            tags = ip_tags[ip][USER_TAGS_FIELD]
            num_type_tags = num_user_tags
        for tag in tags:
            num_type_tags[tag] += 1

    stats = defaultdict(int)
    num_bot_tags = defaultdict(int)
    num_user_tags = defaultdict(int)
    LOGGER.info(f"get_tagged_ips_ctr {idx_ptrn} {ctr}")
    for idx, (ip, status) in enumerate(ip_status.items()):
        if idx % 10_000 == 0:
            LOGGER.debug(f"  on ip {idx} num_ips {sum(stats.values())}...")
        search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[ctr])
        ip_q = Q("bool", filter=[Q("term", **{get_ip_field(idx_ptrn): ip})])
        search = search.query(ip_q)
        ip_in_ctr = search.count() > 0
        if not ip_in_ctr:
            continue
        _update_ip_stats(ip, status, ip_tags, stats, num_bot_tags, num_user_tags)
    return stats, num_bot_tags, num_user_tags


###############################################################################
# GEOIP PIPELINE & REINDEXING


def create_geoip_pipeline():
    p = IngestClient(get_connection())
    p.put_pipeline(
        id=GEOIP_PIPELINE_ID,
        body={
            "description": "Add geoip info",
            "processors": [
                {
                    "geoip": {
                        "field": "ip",
                        "database_file": "GeoLite2-City.mmdb",
                        "properties": [
                            "ip",
                            "country_iso_code",
                            "country_name",
                            "continent_name",
                            "region_iso_code",
                            "region_name",
                            "city_name",
                            "timezone",
                            "location",
                        ],
                        "ignore_missing": True,
                    }
                },
                {
                    "geoip": {
                        "field": "ip",
                        "database_file": "GeoLite2-Country.mmdb",
                        "properties": ["ip", "country_iso_code", "country_name", "continent_name"],
                        "ignore_missing": True,
                    }
                },
                {
                    "geoip": {
                        "field": "ip",
                        "database_file": "GeoLite2-ASN.mmdb",
                        "properties": ["ip", "asn", "organization_name"],
                        "ignore_missing": True,
                    }
                },
            ],
        },
    )


def reindex_geoip(src_idx, dst_idx):
    LOGGER.info(f"reindexing for geoip {src_idx} -> {dst_idx}")
    es = get_connection()
    es.reindex(
        body={
            "conflicts": "proceed",
            "source": {"index": src_idx},
            "dest": {"index": dst_idx, "pipeline": "geoip"},
            "script": {"source": SCRIPT_REINDEX_REMOVE_FILTER_TAGS},
        }
    )
    LOGGER.info(f"done reindexing for geoip {src_idx} -> {dst_idx}")


###############################################################################
# NON-BOT TRAFFIC


def count_nonbot_traffic(idx_ptrn):
    LOGGER.info(f"count_nonbot_traffic {idx_ptrn}")
    non_bot_ips = set(get_status_ips(idx_ptrn, ip_non_bot))
    LOGGER.info(f"  found {len(non_bot_ips)} nonbot ips")
    batch_size = 800  # maxClauseCount=1024, ~200 containers
    ip_batches = utils.batch_iterable(non_bot_ips, n=batch_size)
    total_nonbot_docs = 0
    for idx, batch in enumerate(ip_batches):
        if idx % 100 == 0:
            LOGGER.debug(f"  on {idx*batch_size} with {total_nonbot_docs} nonbot docs")
        search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS)
        ip_batch_q = Q(
            "bool",
            should=[Q("term", **{get_ip_field(idx_ptrn): ip}) for ip in batch],
            minimum_should_match=1,
        )
        search = search.query(ip_batch_q)
        count = search.count()
        LOGGER.debug(f"    batch {idx} count {count} total {total_nonbot_docs}")
        total_nonbot_docs += count
    LOGGER.info(f"  total {total_nonbot_docs} nonbot docs...")
    return total_nonbot_docs


def reindex_nonbot_traffic(idx_ptrn):
    def _get_search(batch):
        search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS)
        ip_batch_q = Q(
            "bool",
            should=[Q("term", **{get_ip_field(idx_ptrn): ip}) for ip in batch],
            minimum_should_match=1,
        )
        search = search.query(ip_batch_q)
        return search

    srvc = idx_ptrn[: idx_ptrn.rfind("-")]
    new_idx_prefix = f"{NON_BOT_IDX_PREFIX}-{srvc}"
    non_bot_ips = set(get_status_ips(idx_ptrn, ip_non_bot))
    LOGGER.info(f"  found {len(non_bot_ips)} nonbot ips")
    ip_batches = utils.batch_iterable(non_bot_ips, n=BATCH_SIZE)
    years = ["2019"]
    months = ["08", "09", "10", "11"]
    LOGGER.info(f"reindex_nonbot_traffic {idx_ptrn}")
    es = get_connection()
    for year in years:
        for month in months:
            src_idx = f"{srvc}-{year}.{month}"
            LOGGER.debug(f"  on index {src_idx}")
            dst_idx = f"{new_idx_prefix}-{year}.{month}"
            for idx, batch in enumerate(ip_batches):
                if idx % 10 == 0:
                    LOGGER.debug(f"    on batch {idx} ip {idx*BATCH_SIZE}/{len(non_bot_ips)}")
                search = _get_search(batch)
                es.reindex(
                    body={
                        "conflicts": "proceed",
                        "source": {
                            "index": src_idx,
                            "query": search.to_dict(),
                        },
                        "dest": {"index": dst_idx},
                    }
                )
