# stdlib
import gzip
from datetime import datetime
import pdb

# 3p
from elasticsearch_dsl import Q, A

# proj
from services import common as c_srvc
from query_enum import QueryEnum
import es_utils
import utils


###############################################################################


LOGGER = utils.get_logger("services_ftp_telnet", "./logs/services_ftp_telnet.log")
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

PLACEBO_IDS = [str(_id) for _id in sorted(list(PLACEBOS.keys()))]
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]


FTP_IDX_PTRN = "ftp-*"
TELNET_IDX_PTRN = "telnet-*"

USER_FIELD_MAP = {FTP_IDX_PTRN: "ftp.user", TELNET_IDX_PTRN: "telnet.user"}

PASS_FIELD_MAP = {FTP_IDX_PTRN: "ftp.password", TELNET_IDX_PTRN: "telnet.password"}

ROCKYOU_FILE = "/mnt/analysis_artifacts/rt_expired/ftp-telnet/rockyou.txt.gz"
MOST_COMMON_ROCKYOU = 20

###############################################################################


def get_user_field(idx_ptrn, keyword=True):
    val = USER_FIELD_MAP[idx_ptrn]
    if keyword:
        val = f"{val}.keyword"
    return val


def get_pass_field(idx_ptrn, keyword=True):
    val = PASS_FIELD_MAP[idx_ptrn]
    if keyword:
        val = f"{val}.keyword"
    return val


def get_rockyou_passwords():
    with gzip.open(ROCKYOU_FILE, "r") as f:
        lines = []
        for line in f:
            if len(lines) >= MOST_COMMON_ROCKYOU:
                break
            try:
                lines.append(line.rstrip().decode())
            except UnicodeDecodeError as e:
                # print(f"{idx} {line} {e}")
                pass
        LOGGER.info(f"Loaded the top {len(lines)} ROCKYOU passwords.")
        return set(lines)


###############################################################################


def get_placebo_creds(idx_ptrn):
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=False, ctids=PLACEBO_IDS, sort_timestamp=False
    )
    user_agg = {"user": A("terms", field=get_user_field(idx_ptrn))}
    pass_agg = {"pwd": A("terms", field=get_pass_field(idx_ptrn))}
    creds_gen = es_utils.scan_aggs(search, [user_agg, pass_agg], size=1_000)
    return creds_gen


###############################################################################


def _tag_by_creds(
    tag,
    idx_ptrn,
    creds,
    ctids=NONPLACEBO_IDS,
    query_type="term",
    keyword=True,
    prefix_wild=False,
    search_only=False,
):
    """
    Parameters
    ----------
    creds : [(user,password)]
    """

    def _get_should(idx_ptrn, query_type, cred, keyword, prefix_wild):
        user, pwd = cred
        user_field = get_user_field(idx_ptrn, keyword=keyword)
        pass_field = get_pass_field(idx_ptrn, keyword=keyword)
        if query_type == "wildcard":
            user = f"{user}*" if not prefix_wild else f"*{user}*"
            pwd = f"{pwd}*" if not prefix_wild else f"*{pwd}*"
        if user is not None and len(user) > 0:
            should = Q(query_type, **{user_field: user}) & Q(query_type, **{pass_field: pwd})
        else:
            should = Q(query_type, **{pass_field: pwd})
        return should

    LOGGER.info(f"Tagging {tag} for {creds[:10]}...")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids, sort_timestamp=False
    )
    must = []
    must_nots = []
    query = Q(
        "bool",
        must=must,
        must_not=must_nots,
        should=[_get_should(idx_ptrn, query_type, cred, keyword, prefix_wild) for cred in creds],
        minimum_should_match=1,
    )
    search = search.query(query)
    if not search_only:
        ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
        ips_gen = es_utils.scan_aggs(search, [ip_agg], size=1_000)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag)
    return search


###############################################################################


def _tag_idx_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in the index pattern's placebo traffic. """
    return c_srvc.tag_idx_placebo_ips(tag, idx_ptrn, search_only=search_only)


def _tag_other_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in other placebo traffic. """
    return c_srvc.tag_other_placebo_ips(tag, idx_ptrn, search_only=search_only)


def _tag_rockyou_passwords(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose password is in the top N rockyou password leak. """
    rockyou_passwords = get_rockyou_passwords()
    LOGGER.info(f"_tag_rockyou_passwords idx_ptrn={idx_ptrn}")
    creds = [(None, pwd) for pwd in rockyou_passwords]
    return [_tag_by_creds(tag, idx_ptrn, creds, search_only=search_only)]


def _tag_domain_passwords(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose password contains the domain of the container. """
    LOGGER.info(f"_tag_domain_passwords idx_ptrn={idx_ptrn}")
    searches = []
    for idx, (ctid, ctr_info) in enumerate(NONPLACEBOS.items()):
        ctr = str(ctid)
        ctr_domain = ctr_info["domain"]
        if idx % 10 == 0:
            LOGGER.info(f"  on ctr {ctr} of {len(NONPLACEBOS)}")
        creds = [(None, ctr_domain)]
        search = _tag_by_creds(
            tag,
            idx_ptrn,
            creds,
            ctids=[ctr],
            query_type="wildcard",
            keyword=True,
            prefix_wild=True,
            search_only=search_only,
        )
        searches.append(search)
    return searches


def _tag_placebo_credentials(tag, idx_ptrn, search_only=False):
    """ Tag all documents who have a (user,password) pair that can be found in placebos. """

    def _extract_user_pass(creds_gen, n=100):
        batch = []
        for bucket in creds_gen:
            if len(batch) == n:
                yield batch
                batch = []
            user = bucket.key.user
            pwd = bucket.key.pwd
            batch.append((user, pwd))
        if len(batch) > 0:
            yield batch

    searches = []
    creds_gen = get_placebo_creds(idx_ptrn)
    creds_gen = _extract_user_pass(creds_gen)
    for idx, batch in enumerate(creds_gen):
        if idx % 1_000 == 0:
            LOGGER.info(f"  _tag_placebo_credentials at batch {idx}...")
        batch_search = _tag_by_creds(tag, idx_ptrn, batch, search_only=search_only)
        searches.append(batch_search)
    return searches


###############################################################################


BOT_TAG_PIPELINE = {
    "placebo-ip": _tag_idx_placebo_ips,
    "other-placebo-ip": _tag_other_placebo_ips,
    "top-20-rockyou": _tag_rockyou_passwords,
    "domain-pw": _tag_domain_passwords,
    "placebo-creds": _tag_placebo_credentials,
}


def tag_ftp(tags, init=False):
    c_srvc.tag(tags, FTP_IDX_PTRN, BOT_TAG_PIPELINE, init=init)


def tag_telnet(tags, init=False):
    c_srvc.tag(tags, TELNET_IDX_PTRN, BOT_TAG_PIPELINE, init=init)


def _scan(tags, idx_ptrn):
    def _init_data(tag, idx_ptrn):
        return {
            "tag": tag,
            "idx_ptrn": idx_ptrn,
            "ips": set(),
            "users": set(),
            "pwds": set(),
            "creds": set(),
        }

    def _process_bucket(data, bucket):
        ip = bucket.key.ip
        user = bucket.key.user
        pwd = bucket.key.pwd
        cred = (user, pwd)
        data["ips"].add(ip)
        data["users"].add(user)
        data["pwds"].add(pwd)
        data["creds"].add(cred)

    def _process_data(data):
        return {
            "tag": data["tag"],
            "idx_ptrn": data["idx_ptrn"],
            "num_ips": len(data["ips"]),
            "num_users": len(data["users"]),
            "num_pwds": len(data["pwds"]),
            "num_creds": len(data["creds"]),
            "creds": [[cred[0], cred[1]] for cred in data["creds"]],
            "users": list(data["users"]),
            "pwds": list(data["pwds"]),
        }

    ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
    user_agg = {"user": A("terms", field=get_user_field(idx_ptrn))}
    pass_agg = {"pwd": A("terms", field=get_pass_field(idx_ptrn))}
    aggs = [ip_agg, user_agg, pass_agg]

    return c_srvc.scan(
        tags, idx_ptrn, BOT_TAG_PIPELINE, aggs, _init_data, _process_bucket, _process_data
    )


def scan_ftp(tags):
    return _scan(tags, FTP_IDX_PTRN)


def scan_telnet(tags):
    return _scan(tags, TELNET_IDX_PTRN)