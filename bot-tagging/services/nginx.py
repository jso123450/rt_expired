# stdlib
from collections import defaultdict
from datetime import datetime
import pdb

# 3p
from elasticsearch_dsl import Q, A, Search

# proj
from services import common as c_srvc
from enums import QueryEnum, TagEnum
import es_utils
import utils


###############################################################################


LOGGER = utils.get_logger("services_nginx")


CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
IDX_PTRN = "nginx-access-*"
FP_IDX_PTRN = "fp-*"

PLACEBO_IDS = [str(_id) for _id in sorted(list(PLACEBOS.keys()))]
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]

BOT_TRAPS = utils.get_bot_traps()

###############################################################################


def _tag_by_paths(
    tag,
    idx_ptrn,
    paths,
    method=None,
    exclude=None,
    query_type="wildcard",
    keyword=False,
    wild_prefix=False,
    wild_suffix=True,
    match_minimum="100%",
    search_only=False,
    ctids=NONPLACEBO_IDS,
    tag_type=TagEnum.BOT,
    placebo=False,
):
    def _get_match(field, path, minimum_should_match):
        return Q(
            "match",
            **{
                field: {
                    "query": path,
                    "operator": "AND",
                    "minimum_should_match": minimum_should_match,
                }
            },
        )

    def _get_should(query_type, path, keyword, wild_prefix, wild_suffix, match_minimum):
        field = "nginx.path" if not keyword else "nginx.path.keyword"
        if query_type == "wildcard":
            wild_prefix = wild_prefix and not path[0] == "/"
            path_q = path
            if wild_prefix:
                path_q = f"*{path_q}"
            if wild_suffix:
                path_q = f"{path_q}*"
            if path_q == path:
                return _get_match(field, path, match_minimum)
            else:
                return Q(query_type, **{field: {"value": path_q}})
        elif query_type == "match":
            return _get_match(field, path, match_minimum)
        elif query_type == "regexp":
            return Q(query_type, **{field: {"value": path, "flags": "ALL"}})

    LOGGER.info(
        f"Tagging {tag} type={query_type} keyword={keyword} prefix={wild_prefix} suffix={wild_suffix} method={method} exclude={exclude} "
    )
    LOGGER.debug(f"  ({len(paths)}) paths {paths[:5]}...{paths[-5:]}")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids, sort_timestamp=False
    )
    must = []
    must_nots = []
    if method is not None:
        must = [Q("term", nginx__method__keyword=method)]
    if exclude is not None:
        excluded = [_get_match("nginx.path", path, match_minimum) for path in exclude]
        must_nots.extend(excluded)
    paths_q = Q(
        "bool",
        must=must,
        must_not=must_nots,
        should=[
            _get_should(query_type, path, keyword, wild_prefix, wild_suffix, match_minimum)
            for path in paths
        ],
        minimum_should_match=1 if len(paths) > 0 else 0,
    )
    search = search.query(paths_q)
    if not search_only:
        ips_gen = es_utils.get_ips(idx_ptrn, search=search)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag, tag_type=tag_type, placebo=placebo)
    return search


###############################################################################


def tag_trap_paths(tag, idx_ptrn, placebo, search_only=False):
    """ Tag all documents whose request path was for a trap path. """
    paths = BOT_TRAPS
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [
        _tag_by_paths(
            tag,
            idx_ptrn,
            paths,
            keyword=True,
            search_only=search_only,
            ctids=ctids,
            placebo=placebo,
        )
    ]


def tag_init_setup(tag, idx_ptrn, placebo, search_only=False):
    """ Tag all documents whose request path contains 'init', 'setup'. """
    paths = ["init.", "setup"]
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [
        _tag_by_paths(tag, idx_ptrn, paths, search_only=search_only, ctids=ctids, placebo=placebo)
    ]


def tag_shell(tag, idx_ptrn, placebo, search_only=False):
    """ Tag all documents whose request path contains 'shell', 'console', or 'wget'. Make sure to exclude 'tattoo' mentions. """
    paths = ["shell", "console", "wget"]
    exclude = ["tattoo"]
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [_tag_by_paths(tag, idx_ptrn, paths, exclude=exclude, search_only=search_only)]


def tag_post_logins(tag, idx_ptrn, placebo, search_only=False):
    """ Tag all documents whose request was a POST to a login endpoint. """
    paths = ["login"]
    method = "POST"
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [_tag_by_paths(tag, idx_ptrn, paths, method=method, search_only=search_only)]


def tag_domains(tag, idx_ptrn, placebo, search_only=False):
    """Tag all documents whose request path was a domain or contained an IP.
    Make sure these requests used CONNECT or asked for a domain different from the server.(?)"""
    # regexp = "^((http(s)?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9]{1,6}:\d{1,5}|(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.(?!$)|$)){4})$"
    # TODO: consider wheter or not we need to ensure the method is CONNECT or that the requested URL is within our data
    regexp = "(http(s)?:\/\/)?([A-Za-z0-9-]+.?)+(:[0-9]+)?\/?"
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [
        _tag_by_paths(
            tag, idx_ptrn, [regexp], query_type="regexp", keyword=True, search_only=search_only
        )
    ]


def tag_path_traversal(tag, idx_ptrn, placebo, search_only=False):
    """Tag all documents whose request path contained a path traversal attack (e.g. "../"). Make sure to get all variants.

    Details can be found at: https://owasp.org/www-community/attacks/Path_Traversal
    """
    paths = utils.get_path_traversals()
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    return [
        _tag_by_paths(tag, idx_ptrn, paths, keyword=True, wild_prefix=True, search_only=search_only)
    ]


def tag_bot_endpoints(tag, idx_ptrn, placebo, search_only=False):
    """ Tag all documents whose request path contained a bot endpoint (db from Babak). """
    paths = utils.get_bot_endpoints()
    ctids = PLACEBO_IDS if placebo else NONPLACEBO_IDS
    sep_paths = dict(
        abs_paths=[],
        extensions=[],
        names=[],
        sub_paths=[],
    )
    for path in paths:
        if path[0] == "/":
            sep_paths["abs_paths"].append(path)
            continue
        has_subpath = path.find("/") > -1
        if has_subpath:
            sep_paths["sub_paths"].append(path)
        is_extension = path[0] == "."
        if is_extension:
            sep_paths["extensions"].append(path)
        else:
            sep_paths["names"].append(path)
    # pdb.set_trace()
    searches = []
    batch_size = 500
    LOGGER.info(f"_tag_bot_endpoints batch_size={batch_size}...")
    for (path_type, paths) in sep_paths.items():
        LOGGER.debug(f"  path_type={path_type}")
        batched_paths = utils.batch_iterable(paths, n=batch_size)
        for batch in batched_paths:
            batch_searches = []
            if path_type == "abs_paths":
                batch_searches.append(
                    _tag_by_paths(
                        tag,
                        idx_ptrn,
                        batch,
                        query_type="wildcard",
                        keyword=True,
                        wild_prefix=False,
                        wild_suffix=True,
                        search_only=search_only,
                    )
                )
            elif path_type == "sub_paths":
                batch_searches.append(
                    _tag_by_paths(
                        tag,
                        idx_ptrn,
                        batch,
                        query_type="match",
                        keyword=False,
                        wild_prefix=False,
                        wild_suffix=False,
                        match_minimum="100%",
                        search_only=search_only,
                    )
                )
                # batch_searches.append(
                #     _tag_by_paths(
                #         tag,
                #         idx_ptrn,
                #         batch,
                #         query_type="wildcard",
                #         keyword=True,
                #         wild_prefix=False,
                #         wild_suffix=True,
                #         match_minimum="100%",
                #         search_only=search_only,
                #     )
                # )
                # batch_searches.append(
                #     _tag_by_paths(
                #         tag,
                #         idx_ptrn,
                #         batch,
                #         query_type="wildcard",
                #         keyword=True,
                #         wild_prefix=True,
                #         wild_suffix=False,
                #         match_minimum="100%",
                #         search_only=search_only,
                #     )
                # )
            elif path_type == "extensions":
                batch_searches.append(
                    _tag_by_paths(
                        tag,
                        idx_ptrn,
                        batch,
                        query_type="wildcard",
                        keyword=False,
                        wild_prefix=True,
                        wild_suffix=False,
                        search_only=search_only,
                    )
                )
            elif path_type == "names":
                batch_searches.append(
                    _tag_by_paths(
                        tag,
                        idx_ptrn,
                        batch,
                        query_type="match",
                        keyword=False,
                        wild_prefix=False,
                        wild_suffix=False,
                        match_minimum="100%",
                        search_only=search_only,
                    )
                )
            searches.extend(batch_searches)
    return searches


def tag_ua_bot(tag, idx_ptrn, placebo, search_only=False):
    LOGGER.info(f"tag_ua_bot {tag} {idx_ptrn}...")
    if placebo:
        raise RuntimeError("tag_ua_bot cannot be run on placebos")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS, sort_timestamp=False
    )
    uas = ["bot", "masscan", "netsystemsresearch", "dataprovider", "zgrab", "TMUFE", "qwant"]
    ua_q = Q(
        "bool",
        filter=[Q("exists", field="nginx.user_agent")],
        should=[Q("wildcard", nginx__user_agent=f"*{ua}*", case_insensitive=True) for ua in uas],
        minimum_should_match=1,
    )
    search = search.query(ua_q)
    if not search_only:
        ips_gen = es_utils.get_ips(idx_ptrn, search=search)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag)
    return search


def tag_ua_fp_exists_browsers(tag, idx_ptrn, placebo, search_only=False):
    def _get_regexes():
        # ver_string = "([0-9]+\.?)+"
        ver_string = ".*"
        browsers = [
            "Chrome",
            "Crome on iOS",
            "Firefox",
            "Safari",
            "Seamonkey",
            "Chromium",
            "Opera",
            "Opera",
            "IE10-",
            "IE11",
        ]
        must = [
            [f".*Chrome\/{ver_string}"],
            [f".*CriOS\/{ver_string}"],
            [f".*Firefox\/{ver_string}"],
            [f".*Safari\/{ver_string}"],
            [f".*Seamonkey\/{ver_string}"],
            [f".*Chromium\/{ver_string}"],
            [f".*OPR\/{ver_string}"],
            [f".*Opera\/{ver_string}"],
            [f".*\; MSIE {ver_string}\;"],
            [f".*Trident\/7.0\;.*rv:{ver_string}"],
        ]
        must_not = [
            [f".*Chromium\/{ver_string}"],
            [f".*Chromium\/{ver_string}"],
            [f".*Seamonkey\/{ver_string}"],
            [f".*Chrome\/{ver_string}", f".*Chromium\/{ver_string}"],
            [],
            [],
            [],
            [],
            [],
            [],
        ]
        return browsers, must, must_not

    def _get_fp_ips():
        ip_idx = es_utils.get_geoip_index(FP_IDX_PTRN)
        search = es_utils.init_query(
            QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None, sort_timestamp=False
        )
        for hit in search.scan():
            yield hit.ip

    def _get_query(must_i, not_i):
        search = Search(index=idx_ptrn)
        start_window = es_utils.TIME_WINDOWS["START"]
        end_window = es_utils.TIME_WINDOWS["END"]
        time_filter = Q(
            "range",
            **{
                "@timestamp": {
                    "gte": start_window,
                    "lt": end_window,
                    "format": es_utils.TIME_FMT,
                }
            },
        )
        ctids_filter = Q(
            "terms_set",
            log__container={
                "terms": NONPLACEBO_IDS,
                "minimum_should_match_script": {"source": "1"},
            },
        )
        ua_filter = [Q("regexp", nginx__user_agent__keyword={"value": _must}) for _must in must_i]
        ua_must_not = [Q("regexp", nginx__user_agent__keyword={"value": _not}) for _not in not_i]
        search = search.query(
            "bool",
            filter=[time_filter, ctids_filter, *ua_filter],
            must_not=ua_must_not,
        )
        return search

    def _yield_srvc_ips(browsers, must, must_not):
        start_time = datetime.now()
        num_ips_per_browser = defaultdict(int)
        for i in range(len(browsers)):
            browser = browsers[i]
            must_i = must[i]
            not_i = must_not[i]
            LOGGER.info(f"  _yield_srvc_ips browser={browser} must={must_i}, not={not_i}")
            # search = es_utils.init_query(
            #     QueryEnum.SEARCH,
            #     idx_ptrn,
            #     filter_time=True,
            #     ctids=NONPLACEBO_IDS,
            #     sort_timestamp=False,
            # )
            search = _get_query(must_i, not_i)
            ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
            _generator = es_utils.scan_aggs(search, [ip_agg], size=1_000)
            for idx, bucket in enumerate(_generator):
                if sum(num_ips_per_browser.values()) % 100_000 == 0:
                    LOGGER.debug(f"    on ip no. {idx}...")
                num_ips_per_browser[browser] += 1
                yield bucket.key.ip
        elapsed = datetime.now() - start_time
        total_yielded = sum(num_ips_per_browser.values())
        LOGGER.info(f"  _yield_srvc_ips yielded {total_yielded} in {elapsed} {num_ips_per_browser}")

    if search_only:
        raise NotImplementedError()
    LOGGER.info(f"tag_ua_fp {tag} {idx_ptrn}...")
    browsers, must, must_not = _get_regexes()
    assert len(must) == len(must_not)
    fp_ips = set(_get_fp_ips())
    srvc_no_fp_ips = set()
    srvc_fp_ips = set()
    _generator = _yield_srvc_ips(browsers, must, must_not)
    batch_size = 10_240
    num_fp = 0
    num_no_fp = 0
    start_time = datetime.now()
    for ip in _generator:
        if not utils.validate_ip(ip):  # err in log
            continue
        found_fp = ip in fp_ips
        if found_fp:
            srvc_fp_ips.add(ip)
            num_fp += 1
        else:
            srvc_no_fp_ips.add(ip)
            num_no_fp += 1
        if len(srvc_no_fp_ips) == batch_size:
            es_utils.tag_ips(idx_ptrn, srvc_no_fp_ips, tag, bucketed=False)
            srvc_no_fp_ips = set()
        if len(srvc_fp_ips) == batch_size:
            es_utils.tag_ips(idx_ptrn, srvc_fp_ips, tag, tag_type=TagEnum.USER, bucketed=False)
            srvc_fp_ips = set()
    if len(srvc_no_fp_ips) > 0:
        es_utils.tag_ips(idx_ptrn, srvc_no_fp_ips, tag, bucketed=False)
    if len(srvc_fp_ips) > 0:
        es_utils.tag_ips(idx_ptrn, srvc_fp_ips, tag, tag_type=TagEnum.USER, bucketed=False)
    elapsed = datetime.now() - start_time
    LOGGER.info(f"tag_ua_fp found_fp={num_fp} no_fp={num_no_fp} in {elapsed}")


def tag_additional_bot_endpoints(tag, idx_ptrn, placebo, search_only=False):
    """ """
    paths = utils.get_additional_bot_endpoints()
    return [
        _tag_by_paths(
            tag,
            idx_ptrn,
            paths,
            query_type="wildcard",
            keyword=True,
            wild_suffix=True,
            search_only=search_only,
        )
    ]


def tag_residual_paths(tag, idx_ptrn, placebo, search_only=False):
    """ """
    searches = []
    paths = utils.get_residual_paths()
    default_query_type = "wildcard"
    sorted_ctrs = utils.get_sorted_containers()
    ctrs = [_id for _id in sorted_ctrs if _id in paths]
    for idx, ctid in enumerate(ctrs):
        if idx % 25 == 0:
            LOGGER.debug(f"  on ctid {ctid} {idx}/{len(ctrs)}")
        ctid_info = paths[ctid]
        ctid_paths = ctid_info["paths"]
        query_type = ctid_info.get("query_type", default_query_type)
        if len(ctid_paths) == 0:
            continue
        keyword = query_type != "match"
        searches.append(
            _tag_by_paths(
                tag,
                idx_ptrn,
                ctid_paths,
                query_type=query_type,
                keyword=keyword,
                wild_prefix=False,
                search_only=search_only,
                ctids=[ctid],
                tag_type=TagEnum.USER,
            )
        )
    return searches


def tag_external_referrer(tag, idx_ptrn, placebo, search_only=False):
    searches = []
    for idx, ctid in enumerate(NONPLACEBO_IDS):
        if idx % 25 == 0:
            LOGGER.debug(f"  on ctr {ctid} {idx}/{len(NONPLACEBO_IDS)}")
        domain_info = CTRS[int(ctid)]
        domain = domain_info["domain"]
        ip = domain_info["ip"]
        search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[ctid])
        referrer_q = Q(
            "bool",
            filter=[
                Q("term", log__container__keyword=str(ctid)),
                Q("exists", field="nginx.referrer"),
            ],
            must_not=[
                Q("term", nginx__referrer__keyword=""),
                Q("term", nginx__referrer__keyword="-"),
                Q("wildcard", nginx__referrer__keyword=f"*{domain}*"),
                Q("wildcard", nginx__referrer__keyword=f"*{ip}*"),
            ],
        )
        search = search.query(referrer_q)
        searches.append(search)
        if not search_only:
            ips_gen = es_utils.get_ips(idx_ptrn, search=search)
            es_utils.tag_ips(idx_ptrn, ips_gen, tag, tag_type=TagEnum.OTHER)
    return searches


###############################################################################

BOT_TAG_PIPELINE = dict(c_srvc.BOT_TAG_PIPELINE)
BOT_TAG_PIPELINE.update(
    {
        "bot-trap": tag_trap_paths,
        "init-setup": tag_init_setup,
        "shell": tag_shell,
        "logins": tag_post_logins,
        "proxy": tag_domains,
        "path-traversal": tag_path_traversal,
        "bot-endpoints": tag_bot_endpoints,
        "additional-be": tag_additional_bot_endpoints,
        "ua-fp_exists": tag_ua_fp_exists_browsers,
        "ua-bot": tag_ua_bot,
    }
)
USER_TAG_PIPELINE = {
    "residual-path": tag_residual_paths,
    "ua-fp_exists": tag_ua_fp_exists_browsers,
}
OTHER_TAG_PIPELINE = {
    "external-referrer": tag_external_referrer,
}
PIPELINES = [BOT_TAG_PIPELINE, USER_TAG_PIPELINE, OTHER_TAG_PIPELINE]


def tag(tags, init=False, placebo=False):
    c_srvc.tag(tags, IDX_PTRN, PIPELINES, init=init)


def scan(tags):
    def _init_data(tag, idx_ptrn):
        return {"tag": tag, "idx_ptrn": idx_ptrn, "ips": set(), "paths": set()}

    def _process_bucket(data, bucket):
        ip = bucket.key.ip
        path = bucket.key.path
        data["ips"].add(ip)
        data["paths"].add(path)

    def _process_data(data):
        return {
            "tag": data["tag"],
            "idx_ptrn": data["idx_ptrn"],
            "num_ips": len(data["ips"]),
            "num_paths": len(data["paths"]),
            "paths": list(data["paths"]),
        }

    ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(IDX_PTRN))}
    path_agg = {"path": A("terms", field="nginx.path.keyword")}
    aggs = [ip_agg, path_agg]

    return c_srvc.scan(tags, IDX_PTRN, PIPELINES, aggs, _init_data, _process_bucket, _process_data)

    # for tag, func in BOT_TAG_PIPELINE.items():
    #     if tag not in _tags:
    #         continue
    #     LOGGER.info(f"nginx scanning: {tag}, {func.__name__}")
    #     tag_searches = func(tag, search_only=True)
    #     tag_paths = set()
    #     tag_ips = set()
    #     for s_idx, search in enumerate(tag_searches):
    #         LOGGER.info(f"  search {s_idx}/{len(tag_searches)}: {search.to_dict()}")
    #         buckets = es_utils.scan_aggs(search, [ip_agg, path_agg], size=1_000)
    #         for idx, bucket in enumerate(buckets):
    #             if idx % 100_000 == 0:
    #                 LOGGER.info(f"  nginx scan {s_idx} on bucket {idx}...")
    #             ip = bucket.key.ip
    #             path = bucket.key.path
    #             tag_paths.add(path)
    #             tag_ips.add(ip)
    #     yield {
    #         "tag": tag,
    #         "num_paths": len(tag_paths),
    #         "num_ips": len(tag_ips),
    #         "paths": list(tag_paths),
    #     }
    # LOGGER.info(f">> nginx scanning finished")