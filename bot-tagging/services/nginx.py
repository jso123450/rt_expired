# stdlib
from datetime import datetime
import re
import pdb

# 3p
from elasticsearch_dsl import Q, A

# proj
from services import common as c_srvc
from query_enum import QueryEnum
import es_utils
import utils


###############################################################################


LOGGER = utils.get_logger("services_nginx", "./logs/services_nginx.log")


IDX_PTRN = "nginx-access-*"
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

PLACEBO_IDS = [str(_id) for _id in sorted(list(PLACEBOS.keys()))]
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]

BOT_TRAPS = utils.get_bot_traps()

###############################################################################


# def _tag_by_paths(tag, paths, method=None, exclude=None):
#     LOGGER.info(f"Tagging {tag} for {paths[:10]}...")
#     ubq = es_utils.init_query(
#         QueryEnum.UBQ, IDX_PTRN, filter_time=True, ctids=NONPLACEBO_IDS, sort_timestamp=False
#     )
#     must = []
#     must_nots = [Q("term", filter_tag=tag)]
#     if method is not None:
#         must = [Q("term", nginx__method__keyword=method)]
#     if exclude is not None:
#         excluded = [Q("match", nginx__path=path) for path in exclude]
#         must_nots.extend(excluded)
#     paths_q = Q(
#         "bool",
#         must=must,
#         must_not=must_nots,
#         should=[Q("match", nginx__path=path) for path in paths],
#         minimum_should_match=1,
#     )
#     ubq = ubq.query(paths_q)
#     ubq = ubq.script(
#         source=es_utils.SCRIPT_ADD_FILTER_TAG,
#         params={"tag": tag},
#     )
#     response = ubq.execute()
#     if not response.success():
#         LOGGER.error(f"  UBQ failed. {response.to_dict()}")
#         return
#     ips_gen = es_utils.get_ips(IDX_PTRN, filter_time=True, tag=tag, ctids=NONPLACEBO_IDS)
#     es_utils.tag_all_ips(IDX_PTRN, tag, ips_gen)


# def _get_hit_ips_gen(search):
#     for hit in search.scan():
#         yield hit.ip


def _tag_by_paths(
    tag,
    idx_ptrn,
    paths,
    method=None,
    exclude=None,
    regexp=None,
    query_type="wildcard",
    keyword=False,
    prefix_wild=False,
    search_only=False,
):
    def _get_should(query_type, path, keyword, prefix_wild):
        # default_field = "nginx.path" if not keyword else "nginx.path.keyword"
        # query_string
        # return Q("query_string", **{"query": path, "default_field": default_field})
        # wildcard
        field = "nginx.path" if not keyword else "nginx.path.keyword"
        if query_type == "wildcard":
            path_val = f"{path}*" if not prefix_wild else f"*{path}*"
            return Q(query_type, **{field: {"value": path_val}})
            # return Q(query_type, nginx__path={"value": path + "*"})
        elif query_type == "match":
            return Q(query_type, **{field: path})
            # return Q(query_type, nginx__path=path)

    LOGGER.info(f"Tagging {tag} for {paths[:10]} with regexp={regexp}...")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS, sort_timestamp=False
    )
    must = []
    must_nots = []
    # must_nots = [Q("exists", field=es_utils.FILTER_TAG_FIELD)]
    # must_nots = [Q("term", bot_filter_tag=tag)]
    if method is not None:
        must = [Q("term", nginx__method__keyword=method)]
    if exclude is not None:
        excluded = [Q("match", nginx__path=path) for path in exclude]
        must_nots.extend(excluded)
    paths_q = Q(
        "bool",
        must=must,
        must_not=must_nots,
        should=[_get_should(query_type, path, keyword, prefix_wild) for path in paths],
        minimum_should_match=1 if len(paths) > 0 else 0,
    )
    if regexp is not None:
        paths_q = paths_q & Q(
            "regexp", nginx__path__keyword={"value": re.escape(regexp), "flags": "ALL"}
        )
    search = search.query(paths_q)
    if not search_only:
        ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
        ips_gen = es_utils.scan_aggs(search, [ip_agg], size=1_000)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag)
    return search


###############################################################################


def _tag_nginx_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose client IP was found in nginx placebo traffic. """
    return c_srvc.tag_idx_placebo_ips(tag, idx_ptrn, search_only=search_only)


def _tag_other_placebo_ips(tag, idx_ptrn, search_only=False):
    return c_srvc.tag_other_placebo_ips(tag, idx_ptrn, search_only=search_only)


def _tag_trap_paths(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose request path was for a trap path. """
    paths = BOT_TRAPS
    return [_tag_by_paths(tag, idx_ptrn, paths, keyword=True, search_only=search_only)]


def _tag_init_setup(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose request path contains 'init', 'setup'. """
    paths = ["init.", "setup"]
    return [_tag_by_paths(tag, idx_ptrn, paths, search_only=search_only)]


def _tag_shell(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose request path contains 'shell', 'console', or 'wget'. Make sure to exclude 'tattoo' mentions. """
    paths = ["shell", "console", "wget"]
    exclude = ["tattoo"]
    return [_tag_by_paths(tag, idx_ptrn, paths, exclude=exclude, search_only=search_only)]


def _tag_post_logins(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose request was a POST to a login endpoint. """
    paths = ["login"]
    method = "POST"
    return [_tag_by_paths(tag, idx_ptrn, paths, method=method, search_only=search_only)]


def _tag_domains(tag, search_only=False):
    """ Tag all documents whose request path was a domain or contained an IP. Make sure these requests used CONNECT or asked for a domain different from the server. """
    # method = "CONNECT"
    # prob will need to use a painless script in UBQ
    # raise NotImplementedError()

    # regexp = "((http(s)?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9]{1,6}:\d{1,5}|(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.(?!$)|$)){4})"
    # search = _tag_by_paths(tag, [], regexp=regexp, search_only=search_only)
    # pdb.set_trace()
    # for hit in search.scan():
    #     pass
    pass


def _tag_path_traversal(tag, idx_ptrn, search_only=False):
    """Tag all documents whose request path contained a path traversal attack (e.g. "../"). Make sure to get all variants.

    Details can be found at: https://owasp.org/www-community/attacks/Path_Traversal
    """
    paths = utils.get_path_traversals()
    return [
        _tag_by_paths(tag, idx_ptrn, paths, keyword=True, prefix_wild=True, search_only=search_only)
    ]


def _tag_bot_endpoints(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose request path contained a bot endpoint (db from Babak). """
    paths = utils.get_bot_endpoints()
    batch_size = 500
    batched_paths = utils.batch_iterable(paths, n=batch_size)
    LOGGER.info(f"_tag_bot_endpoints batch_size={batch_size}...")
    searches = []
    for idx, batch in enumerate(batched_paths):
        if idx % 10 == 0:
            LOGGER.info(f"  at batch {idx}...")
        batch_search = _tag_by_paths(tag, idx_ptrn, batch, search_only=search_only)
        searches.append(batch_search)
    return searches


###############################################################################


BOT_TAG_PIPELINE = {
    "placebo-ip": _tag_nginx_placebo_ips,
    "other-placebo-ip": _tag_other_placebo_ips,
    "bot-trap": _tag_trap_paths,
    "init-setup": _tag_init_setup,
    "shell": _tag_shell,
    "logins": _tag_post_logins,
    "proxy": _tag_domains,
    "path-traversal": _tag_path_traversal,
    "bot-endpoints": _tag_bot_endpoints,
}


def tag(tags, init=False):
    c_srvc.tag(tags, IDX_PTRN, BOT_TAG_PIPELINE, init=init)


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

    return c_srvc.scan(
        tags, IDX_PTRN, BOT_TAG_PIPELINE, aggs, _init_data, _process_bucket, _process_data
    )

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