# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
# from IPython import get_ipython

# %%
# get_ipython().run_line_magic("load_ext", "autotime")

# %%
from collections import defaultdict
import gzip
import json
import logging
from pathlib import Path
import pdb

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, A, Q
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils


# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

# constants
INDICES = ["ftp-*", "telnet-*"]
SEP = CONFIG["IO"]["CSV_SEP"]

# artifacts
BASE_DIR = Path(CONFIG["ARTIFACT_DIR"]) / "ftp-telnet"
DATA_DIR = BASE_DIR / "es"
PLOTS_DIR = BASE_DIR / "plots"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

FTP_DF = DATA_DIR / "ftp.csv"
TELNET_DF = DATA_DIR / "telnet.csv"

ROCKYOU_FILE = DATA_DIR / "rockyou.txt.gz"


# globals
LOGGER = utils.get_logger("ftp-telnet_stats", BASE_DIR / "ftp-telnet.log", logging.INFO)


# %%
def get_ftp_telnet_reqs(idx_ptrn, csv):
    def _process_bucket(bucket):
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        user = bucket.key.user
        password = bucket.key.password
        ip, domain = es_utils.get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:
            return None
        row = [ctid, client_ip, user, password, str(bucket.doc_count)]
        output = f"{SEP.join(row)}\n"
        return output

    srvc = idx_ptrn[:idx_ptrn.index("-*")]
    source_aggs = [
        {"ctid": A("terms", field="container.id.keyword")},
        {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))},
        {"user": A("terms", field=f"{srvc}.user.keyword")},
        {"password": A("terms", field=f"{srvc}.password.keyword")}
    ]
    source_aggs_map = {idx_ptrn: source_aggs}
    cols = ["id", "client_ip", "user", "password", "count"]
    df = es_utils.query_scan_idx_aggs(
        csv, source_aggs_map, [idx_ptrn], _process_bucket, cols, filter_time=True
    )
    df = df.astype({
        "id": "string",
        "client_ip": "string",
        "user": "string",
        "password": "string",
    })
    return df

ftp_df = get_ftp_telnet_reqs("ftp-*", FTP_DF)
telnet_df = get_ftp_telnet_reqs("telnet-*", TELNET_DF)

# %%
all_srvc_unique_ips = es_utils.get_srvc_unique_ips(
    es_utils.ALL_SRVC_UNIQUE_IPS_DF, filter_time=False
)
filtered_srvc_unique_ips = es_utils.get_srvc_unique_ips(
    es_utils.FILTERED_SRVC_UNIQUE_IPS_DF, filter_time=True
)
LOGGER.info(
    f"all shape {all_srvc_unique_ips.shape}, filtered shape {filtered_srvc_unique_ips.shape}"
)

placebos, _, _, _ = es_utils.filter_placebo_ips(
    all_srvc_unique_ips
)  # get placebo ips from entire range
_, nonplacebos, _, _ = es_utils.filter_placebo_ips(
    filtered_srvc_unique_ips
)  # get nonplacebos from window

# %%
def get_filtered_placebos(df):
    filtered_df = df[~df["client_ip"].isin(placebos["client_ip"])]
    placebo_df = df[df["client_ip"].isin(placebos["client_ip"])]
    return filtered_df, placebo_df

ftp_filtered_1_df, ftp_placebo_df = get_filtered_placebos(ftp_df)
telnet_filtered_1_df, telnet_placebo_df = get_filtered_placebos(telnet_df)

# %%
def get_rockyou_passwords():
    with gzip.open(ROCKYOU_FILE, "r") as f:
        return pd.Series(f.readlines())

def filter_same_creds(filtered, placebo):
    common = filtered.merge(placebo, how="inner", on=["user", "password"])
    nonplacebo_creds = filtered[
        (~filtered.user.isin(common.user)) | (~filtered.password.isin(common.password))
    ]
    placebo_creds = filtered[
        (filtered.user.isin(common.user)) & (filtered.password.isin(common.password))
    ]
    return nonplacebo_creds, placebo_creds

def filter_rockyou_passwords(df, rockyou):
    non_rockyou_rows = df[~df["password"].isin(rockyou)]
    rockyou_rows = df[df["password"].isin(rockyou)]
    return non_rockyou_rows, rockyou_rows

rockyou_passwords = get_rockyou_passwords()
ftp_filtered_2_df, ftp_filtered_2_placebo_df = filter_same_creds(ftp_filtered_1_df, ftp_placebo_df)
ftp_filtered_3_df, ftp_filtered_3_rockyou_df = filter_rockyou_passwords(ftp_filtered_2_df, rockyou_passwords)

telnet_filtered_2_df, telnet_filtered_2_placebo_df = filter_same_creds(telnet_filtered_1_df, telnet_placebo_df)
telnet_filtered_3_df, telnet_filtered_3_rockyou_df = filter_rockyou_passwords(telnet_filtered_2_df, rockyou_passwords)

