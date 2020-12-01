# stdlib
from collections import defaultdict
import pdb

# 3p
from elasticsearch.helpers import bulk
from elasticsearch_dsl import Q, A, Search, UpdateByQuery
from elasticsearch_dsl.connections import get_connection

# proj
from query_enum import QueryEnum
import utils


###############################################################################

CONFIG = utils.get_config()
LOGGER = utils.get_logger("es_utils", "./logs/es_utils.log")

TIME_WINDOWS = CONFIG["TIME"]["WINDOWS"]
TIME_FMT = CONFIG["TIME"]["FMT"]

NONPLACEBOS = utils.get_nonplacebos()

INDICES_IP_MAPPING = {
    "nginx-access-*": "ip.keyword",
    "postfix-*": "postfix_client_ip.keyword",
    "telnet-*": "ip.keyword",
    "ftp-*": "ip.keyword",
    "ssh-*": "ssh.ip.keyword",
}
FILTER_TAG_FIELD = "bot_filter_tag"
SCRIPT_SET_FILTER_TAG = f"ctx._source.{FILTER_TAG_FIELD} = params.tag"

FILTER_TAGS_FIELD = "bot_filter_tags"
SCRIPT_ADD_FILTER_TAG = f""" if (ctx._source.containsKey("{FILTER_TAGS_FIELD}")) {{
    if (!ctx._source.{FILTER_TAGS_FIELD}.contains(params.tag)) {{
        ctx._source.{FILTER_TAGS_FIELD}.add(params.tag);
    }}
}} else {{
    ctx._source.{FILTER_TAGS_FIELD} = [params.tag];
}}
"""
CONST_LOG_EVERY_N = 100_000
BATCH_SIZE = 1024

###############################################################################


def get_ip_field(idx_ptrn):
    return INDICES_IP_MAPPING[idx_ptrn]


def get_ip_index(idx_ptrn):
    srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
    new_idx = f"ips-{srvc}"
    return new_idx


###############################################################################


def scan_aggs(search, source_aggs, inner_aggs={}, size=10):
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
        q = q.query(
            "terms_set",
            log__container={"terms": ctids, "minimum_should_match_script": {"source": "1"}},
        )
    if sort_timestamp:
        q = q.sort({"log.container.keyword": {"order": "asc"}}, {"@timestamp": {"order": "asc"}})
    return q


###############################################################################


def get_ips(idx_ptrn, filter_time=False, tag=None, ctids=None):
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
        buckets of unique IPs from scan_aggs
    """
    ip_agg = {"ip": A("terms", field=get_ip_field(idx_ptrn))}
    search = init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=filter_time, ctids=ctids)
    if tag is not None:
        search = search.query(
            "terms_set",
            filter_tag={"terms": tag, "minimum_should_match_script": {"source": "1"}},
        )
    LOGGER.debug(f"get_all_ips search {search.to_dict()}")
    _generator = scan_aggs(search, [ip_agg], size=1_000)
    return _generator


def extract_ips_from_buckets(ip_generator, n=1):
    batch = []
    for bucket in ip_generator:
        if len(batch) == n:
            yield batch
            batch = []
        batch.append(bucket.key.ip)
    if len(batch) > 0:
        yield batch
    # return set(bucket.key.ip for bucket in ip_generator)


def extract_ips_from_hits(hit_ips, n=1):
    ips = set(ip for ip in hit_ips)
    batch = []
    for ip in ips:
        if len(batch) == n:
            yield batch
            batch = []
        batch.append(ip)


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
#         ubq = ubq.query("term", ip__keyword=ip)  # query only for the ip
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


def _generate_ip_entries(index, ips, tags=[]):
    for ip in ips:
        entry = dict(_id=ip, _index=index, _source=dict(ip=ip, filter_tags=tags))
        yield entry


def _update_ip_entries(index, ips, tag):
    ubq = init_query(QueryEnum.UBQ, index, filter_time=False, ctids=None, sort_timestamp=False)
    query = Q(
        "bool",
        must=[],
        must_not=[],
        should=[Q("term", ip__keyword=ip) for ip in ips],
        minimum_should_match=1,
    )
    ubq = ubq.query(query)
    ubq = ubq.script(
        source=SCRIPT_ADD_FILTER_TAG,
        params={"tag": tag},
    )
    response = ubq.execute()
    # LOGGER.debug(f"_update_ip_entries {response.to_dict()}")
    return response.updated


def init_ip_index(idx_ptrn):
    pdb.set_trace()
    nonplacebos = sorted(list(NONPLACEBOS.keys()))
    nonplacebos = [str(_id) for _id in nonplacebos]
    ips_gen = get_ips(idx_ptrn, filter_time=True, tag=None, ctids=nonplacebos)

    ip_index = get_ip_index(idx_ptrn)
    unique_ips = extract_ips_from_buckets(ips_gen, n=1)
    unique_ips = [ip for sublist in unique_ips for ip in sublist]

    LOGGER.debug(f"init_bot_index {idx_ptrn}...")

    response = bulk(
        get_connection(),
        _generate_ip_entries(ip_index, unique_ips, tags=[]),
        max_retries=CONFIG["ELASTICSEARCH"]["MAX_RETRIES"],
    )
    LOGGER.debug(f"> response {response}")


def tag_ips(idx_ptrn, ips_gen, tag):
    # pdb.set_trace()
    ip_index = get_ip_index(idx_ptrn)
    ips = extract_ips_from_buckets(ips_gen, n=BATCH_SIZE)
    # if bucketed:
    #     ips = extract_ips_from_buckets(ips_gen, n=1024)
    # else:
    #     ips = extract_ips_from_hits(ips_gen, n=1024)
    LOGGER.info(f"  tag_ips for {tag} batch_size={BATCH_SIZE}")
    num_ips = 0
    for idx, batch in enumerate(ips):
        if idx % 10 == 0:
            LOGGER.info(f"    at batch {idx}...")
        batch_ips = _update_ip_entries(ip_index, batch, tag)
        num_ips += batch_ips
    LOGGER.info(f"  tagged {num_ips} IPs with {tag}")


###############################################################################


def _determine_tags(idx_ptrn, ips):
    tags_to_ips = defaultdict(set)
    untagged_ips = set()
    search = init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=False, ctids=None, sort_timestamp=False
    )
    query = Q(
        "bool",
        must=[],
        must_not=[],
        should=[Q("term", ip__keyword=ip) for ip in ips],
        minimum_should_match=1,
    )
    search = search.query(query)
    for hit in search.scan():
        if FILTER_TAGS_FIELD not in hit:
            untagged_ips.add(hit.ip)
            continue
        hit_tags = hit[FILTER_TAGS_FIELD]
        for tag in hit_tags:
            tags_to_ips[tag].add(hit.ip)
        if hit_tags is None or len(hit_tags) == 0:
            untagged_ips.add(hit.ip)
    return tags_to_ips, untagged_ips


def get_tagged_ips(idx_ptrn, ips_gen):
    ip_index = get_ip_index(idx_ptrn)
    ips = extract_ips_from_buckets(ips_gen, n=BATCH_SIZE)
    tags_to_ips = defaultdict(set)
    tagged_ips = set()
    untagged_ips = set()
    for idx, batch in enumerate(ips):
        if idx % 10 == 0:
            LOGGER.info(f"    at batch {idx}...")
        batch_tagged_ips, batch_untagged_ips = _determine_tags(ip_index, batch)
        for tag, ips in batch_tagged_ips.items():
            tags_to_ips[tag].update(ips)
            tagged_ips.update(ips)
        untagged_ips.update(batch_untagged_ips)
    num_tagged = len(tagged_ips)
    num_untagged = len(untagged_ips)
    num_ips = num_untagged + num_tagged
    LOGGER.info(f"  idx_ptrn {idx_ptrn} has {num_tagged}/{num_ips} IPs tagged")
    return (tags_to_ips, untagged_ips)
