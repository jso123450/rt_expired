# stdlib
import json
import pdb

# 3p
import pandas as pd
import matplotlib.pyplot as plt

# proj
from services import nginx, ftp_telnet
import utils
import es_utils


###############################################################################

LOGGER = utils.get_logger("ctr_status", "./logs/ctr_status.log")
NONPLACEBOS = utils.get_nonplacebos()

IDX_PTRN_TAGS = {
    "nginx-access-*": nginx.BOT_TAG_PIPELINE.keys(),
    "ftp-*": [],
    "telnet-*": [],
    "ssh-*": [],
}

###############################################################################


def load_ctr_status(status_file):
    ctr_status = {}
    with open(status_file, "r") as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            o = json.loads(line)
            ctid = o["ctid"]
            del o["ctid"]
            ctr_status[ctid] = o
    return ctr_status


def aggregate_num_tagged(idx_ptrn, ctr_status):
    idx_tags = IDX_PTRN_TAGS[idx_ptrn]

    rows = []
    cols = ["ctid", *idx_tags, "untagged"]
    for ctid, ctr_info in ctr_status.items():
        tag_ips = [ctr_info["tags_to_ips"].get(tag, []) for tag in idx_tags]
        num_tag_ips = [len(ips) for ips in tag_ips]
        untagged = ctr_info["untagged"]
        row = [ctid, *num_tag_ips, untagged]
        rows.append(row)
    return pd.DataFrame(rows, columns=cols)


def plot_status(idx_ptrn, status_file):
    ctr_status = load_ctr_status(status_file)
    df = aggregate_num_tagged(ctr_status)
    pdb.set_trace()
    print("hi")


###############################################################################


def _get_ctr_status(idx_ptrn, ctr):
    LOGGER.info(f"ctr status for {idx_ptrn} {ctr}")
    ips_gen = es_utils.get_ips(idx_ptrn, filter_time=True, tag=None, ctids=[ctr])
    tags_to_ips, untagged_ips = es_utils.get_tagged_ips(idx_ptrn, ips_gen)
    tags_to_ips_list = {k: list(v) for k, v in tags_to_ips.items()}
    untagged_ips_list = list(untagged_ips)
    ctr_status = dict(ctid=ctr, tags_to_ips=tags_to_ips_list, untagged=untagged_ips_list)
    return ctr_status


def get_containers_status(idx_ptrn, results_file):
    pdb.set_trace()
    ctrs = [str(ctr) for ctr in NONPLACEBOS]
    with open(results_file, "a+") as f:
        for ctr in ctrs:
            ctr_status = _get_ctr_status(idx_ptrn, ctr)
            out = f"{json.dumps(ctr_status)}\n"
            f.write(out)