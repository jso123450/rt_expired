# stdlib
import pdb

# 3p
from elasticsearch_dsl import Q, A

# proj
from services import common as c_srvc
from enums import QueryEnum, TagEnum
import es_utils
import utils

from services.common import (
    SSH_IDX_PTRN,
    MOST_COMMON_ROCKYOU,
    get_user_field,
    get_pass_field,
    tag_idx_placebo_ips,
    tag_other_placebo_ips,
    tag_mirai_ips,
    tag_other_services_bot_ips,
    tag_blocklist_ips,
    _tag_rockyou_passwords,
    _tag_domain_passwords,
    _tag_placebo_credentials,
    _tag_repeated_credentials,
)

###############################################################################


LOGGER = utils.get_logger("services_ssh")
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]


###############################################################################


def _tag_by_cowrie_events(tag, idx_ptrn, events, tag_type=TagEnum.USER, search_only=False):
    LOGGER.info(f"Tagging {tag} for {events} with tag_type={tag_type}...")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS, sort_timestamp=False
    )
    paths_q = Q(
        "bool",
        must=[],
        must_not=[],
        should=[Q("term", ssh__eventid__keyword=event) for event in events],
        minimum_should_match=1 if len(events) > 0 else 0,
    )
    search = search.query(paths_q)
    if not search_only:
        ips_gen = es_utils.get_ips(idx_ptrn, search=search)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag, tag_type=tag_type)
    return search


###############################################################################


def _tag_login_success(tag, idx_ptrn, search_only=False):
    eventid = "cowrie.login.success"
    return [_tag_by_cowrie_events(tag, idx_ptrn, [eventid], bot=True, search_only=search_only)]


def _tag_public_key(tag, idx_ptrn, search_only=False):
    eventid = "cowrie.client.fingerprint"
    return [_tag_by_cowrie_events(tag, idx_ptrn, [eventid], bot=False, search_only=search_only)]


def _tag_terminal_size(tag, idx_ptrn, search_only=False):
    eventid = "cowrie.client.size"
    return [_tag_by_cowrie_events(tag, idx_ptrn, [eventid], bot=False, search_only=search_only)]


###############################################################################

BOT_TAG_PIPELINE = dict(c_srvc.BOT_TAG_PIPELINE)
BOT_TAG_PIPELINE.update(
    {
        f"top-{MOST_COMMON_ROCKYOU}-rockyou": _tag_rockyou_passwords,
        "domain-pw": _tag_domain_passwords,
        "placebo-creds": _tag_placebo_credentials,
        "repeated-creds": _tag_repeated_credentials,
        "login-success": _tag_login_success,
        "public-key": _tag_public_key,
        "terminal-size": _tag_terminal_size,
    }
)
PIPELINES = [BOT_TAG_PIPELINE]


def tag(tags, init=False):
    c_srvc.tag(tags, SSH_IDX_PTRN, PIPELINES, init=init)


def scan(tags):
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

    ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(SSH_IDX_PTRN))}
    user_agg = {"user": A("terms", field=get_user_field(SSH_IDX_PTRN))}
    pass_agg = {"pwd": A("terms", field=get_pass_field(SSH_IDX_PTRN))}
    aggs = [ip_agg, user_agg, pass_agg]

    return c_srvc.scan(
        tags, SSH_IDX_PTRN, PIPELINES, aggs, _init_data, _process_bucket, _process_data
    )
