from collections import defaultdict
from datetime import datetime
from pathlib import Path
import sys
import pdb

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))

from elasticsearch_dsl import A, Q, Search
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

from enums import QueryEnum, TagEnum
import utils
import es_utils

IDX_PTRNS = ["nginx-access-*", "ssh-*", "telnet-*", "ftp-*"]
LOGGER = utils.get_logger("one_off")
NONPLACEBOS = utils.get_nonplacebos()

DATA_DIR = MAIN_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE_RAW = DATA_DIR / "bucket_domains.csv"
DATA_FILE_BUCKETED = DATA_DIR / "bucketed.csv"

SEP_CSV = ","


def get_num_ctid_srvc_reqs(ctid, idx_ptrn):
    search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[str(ctid)])
    # file_agg = {"file": A("terms", field="log.path.keyword")}
    # line_agg = {"line": A("terms", field="log.line")}
    # _generator = es_utils.scan_aggs(search, [file_agg, line_agg], size=1_000)
    # srvc_hits = len(list(_generator))
    return search.count()


def download():
    cols = ["ctid", "idx_ptrn", "num_requests"]
    utils.write_iter_line(DATA_FILE_RAW, cols, SEP_CSV)
    LOGGER.info(f"downloading...")
    for idx, ctid in enumerate(NONPLACEBOS):
        LOGGER.debug(f"idx {idx} ctid {ctid}")
        ctid_reqs = {ptrn: get_num_ctid_srvc_reqs(ctid, ptrn) for ptrn in IDX_PTRNS}
        for ptrn, num_reqs in ctid_reqs.items():
            row = [str(ctid), ptrn, str(num_reqs)]
            utils.write_iter_line(DATA_FILE_RAW, row, SEP_CSV)


def load_data():
    df = pd.read_csv(DATA_FILE_RAW, sep=SEP_CSV)
    df = df.astype({"ctid": "category", "idx_ptrn": "string", "num_requests": "int64"})
    return df


def transform(df):
    cols = ["ctid", *IDX_PTRNS, "total"]
    rows = []
    for ctid in NONPLACEBOS:
        tmp = df[df["ctid"] == ctid]
        num_requests = tmp.num_requests.to_list()
        row = [ctid, *num_requests, sum(num_requests)]
        rows.append(row)
    new_df = pd.DataFrame(rows, columns=cols)
    new_df = new_df.astype(
        {
            "ctid": "category",
            "nginx-access-*": "int64",
            "ssh-*": "int64",
            "telnet-*": "int64",
            "ftp-*": "int64",
            "total": "int64",
        }
    )
    return new_df


def bucket_domains(df):
    def _get_buckets(df):
        # tmp = df.sort_values(by=["total"], ascending=[True])
        # num = tmp.shape[0]
        # bounds = [round(num / 3), round(2 * num / 3)]
        # buckets = [tmp.iloc[i].total for i in bounds]
        # buckets = [1_000_000, 10_000_000]
        buckets = np.percentile(df.total, [50, 90])
        return buckets

    def _apply_bucket(x, buckets):
        if x < buckets[0]:
            return 0
        elif buckets[0] <= x and x < buckets[1]:
            return 1
        else:
            return 2

    buckets = _get_buckets(df)
    df["bucket"] = df.total.apply(_apply_bucket, args=(buckets,))
    df = df.sort_values(by=["bucket", "total"], ascending=[False, False])
    return df


def save_buckets(df):
    df.to_csv(DATA_FILE_BUCKETED, index=False)


def main():
    if not DATA_FILE_RAW.exists():
        download()
    data = load_data()
    df = transform(data)
    pdb.set_trace()
    df = bucket_domains(df)
    save_buckets(df)


if __name__ == "__main__":
    main()