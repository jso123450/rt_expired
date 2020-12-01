# stdlib
from datetime import datetime
import pdb

# 3p
from elasticsearch_dsl import Q, A

# proj
from query_enum import QueryEnum
import es_utils
import utils


###############################################################################


LOGGER = utils.get_logger("nginx", "./logs/nginx.log")


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


def _get_hit_ips_gen(search):
    for hit in search.scan():
        yield hit.ip


def _tag_by_paths(tag, paths, method=None, exclude=None):
    LOGGER.info(f"Tagging {tag} for {paths[:10]}...")
    search = es_utils.init_query(
        QueryEnum.SEARCH, IDX_PTRN, filter_time=True, ctids=NONPLACEBO_IDS, sort_timestamp=False
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
        should=[Q("match", nginx__path=path) for path in paths],
        minimum_should_match=1,
    )
    search = search.query(paths_q)
    ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(IDX_PTRN))}
    ips_gen = es_utils.scan_aggs(search, [ip_agg], size=1_000)
    # query = query.script(
    #     source=es_utils.SCRIPT_SET_FILTER_TAG,
    #     params={"tag": tag},
    # )
    # search = search.params(conflicts="proceed", refresh=True)
    # hit_ips_gen = _get_hit_ips_gen(search)

    # pdb.set_trace()
    # response = query.execute()
    # LOGGER.debug(f"_tag_by_paths {response.to_dict()}")
    # ips_gen = es_utils.get_ips(IDX_PTRN, filter_time=True, tag=tag, ctids=NONPLACEBO_IDS)
    es_utils.tag_ips(IDX_PTRN, ips_gen, tag)


###############################################################################


def _tag_nginx_placebo_ips(tag):
    """ Tag all documents whose client IP was found in nginx placebo traffic. """
    indices = ["nginx-access-*"]
    _tag_placebo_ips(tag, indices)


def _tag_other_placebo_ips(tag):
    indices = ["ftp-*", "telnet-*", "ssh-*"]
    _tag_placebo_ips(tag, indices)


def _tag_placebo_ips(tag, indices):
    """ Tag all documents whose client IP was found in other placebo traffic. """
    for idx_ptrn in indices:
        LOGGER.info(f"_tag_placebo_ips idx_ptrn={idx_ptrn}")
        ips_gen = es_utils.get_ips(idx_ptrn, filter_time=False, tag=None, ctids=PLACEBO_IDS)
        es_utils.tag_ips(IDX_PTRN, ips_gen, tag)


def _tag_trap_paths(tag):
    """ Tag all documents whose request path was for a trap path. """
    paths = BOT_TRAPS
    _tag_by_paths(tag, paths)


def _tag_init_setup(tag):
    """ Tag all documents whose request path contains '.init.' or 'setup'. """
    paths = [".init.", "setup"]
    _tag_by_paths(tag, paths)


def _tag_shell(tag):
    """ Tag all documents whose request path contains 'shell', 'console', or 'wget'. Make sure to exclude 'tattoo' mentions. """
    paths = ["shell", "console", "wget"]
    exclude = ["tattoo"]
    _tag_by_paths(tag, paths, exclude=exclude)


def _tag_post_logins(tag):
    """ Tag all documents whose request was a POST to a login endpoint. """
    paths = ["login"]
    method = "POST"
    _tag_by_paths(tag, paths, method=method)


def _tag_domains(tag):
    """ Tag all documents whose request path was a domain or contained an IP. Make sure these requests used CONNECT or asked for a domain different from the server. """
    # method = "CONNECT"
    # prob will need to use a painless script in UBQ
    # raise NotImplementedError()
    pass


def _tag_path_traversal(tag):
    """Tag all documents whose request path contained a path traversal attack (e.g. "../"). Make sure to get all variants.

    Details can be found at: https://owasp.org/www-community/attacks/Path_Traversal
    """
    paths = utils.get_path_traversals()
    _tag_by_paths(tag, paths)


def _tag_bot_endpoints(tag):
    """ Tag all documents whose request path contained a bot endpoint (db from Babak). """
    paths = utils.get_bot_endpoints()
    batch_size = 500
    batched_paths = utils.batch_iterable(paths, n=batch_size)
    LOGGER.info(f"_tag_bot_endpoints batch_size={batch_size}...")
    for idx, batch in enumerate(batched_paths):
        if idx % 10 == 0:
            LOGGER.info(f"  at batch {idx}...")
        _tag_by_paths(tag, batch)


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


def tag(_tags, init=False):
    if init:
        es_utils.init_ip_index(IDX_PTRN)
    tags = set(BOT_TAG_PIPELINE.keys()) if _tags is None or len(_tags) == 0 else set(_tags)
    pipeline_start = datetime.now()
    for tag, func in BOT_TAG_PIPELINE.items():
        if tag not in tags:
            continue
        start_time = datetime.now()
        LOGGER.info(f"nginx tagging: {tag}, {func.__name__}")
        func(tag)
        elapsed = datetime.now() - start_time
        LOGGER.info(f"{tag}, {func.__name__} completed in {elapsed.total_seconds()} seconds")
    elapsed = datetime.now() - pipeline_start
    LOGGER.info(f">> nginx pipeline completed in {elapsed.total_seconds()} seconds")