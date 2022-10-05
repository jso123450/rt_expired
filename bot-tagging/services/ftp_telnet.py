# stdlib
import pdb

# 3p
from elasticsearch_dsl import Q, A

# proj
from services import common as c_srvc
import es_utils
import utils

from services.common import (
    FTP_IDX_PTRN,
    TELNET_IDX_PTRN,
    MOST_COMMON_ROCKYOU,
    get_user_field,
    get_pass_field,
    _tag_rockyou_passwords,
    _tag_domain_passwords,
    _tag_placebo_credentials,
    _tag_repeated_credentials,
)


###############################################################################


LOGGER = utils.get_logger("services_ftp_telnet")
NONPLACEBOS = utils.get_nonplacebos()


###############################################################################

BOT_TAG_PIPELINE = dict(c_srvc.BOT_TAG_PIPELINE)
BOT_TAG_PIPELINE.update(
    {
        f"top-{MOST_COMMON_ROCKYOU}-rockyou": _tag_rockyou_passwords,
        "domain-pw": _tag_domain_passwords,
        "placebo-creds": _tag_placebo_credentials,
        "repeated-creds": _tag_repeated_credentials,
    }
)
PIPELINES = [BOT_TAG_PIPELINE]


def tag_ftp(tags, init=False):
    c_srvc.tag(tags, FTP_IDX_PTRN, PIPELINES, init=init)


def tag_telnet(tags, init=False):
    c_srvc.tag(tags, TELNET_IDX_PTRN, PIPELINES, init=init)


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

    return c_srvc.scan(tags, idx_ptrn, PIPELINES, aggs, _init_data, _process_bucket, _process_data)


def scan_ftp(tags):
    return _scan(tags, FTP_IDX_PTRN)


def scan_telnet(tags):
    return _scan(tags, TELNET_IDX_PTRN)