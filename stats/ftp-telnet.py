# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from IPython import get_ipython

# %%
get_ipython().run_line_magic("load_ext", "autotime")

# %%
from collections import defaultdict
import gzip
import json
import logging
from pathlib import Path
import pdb
import re

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, A, Q
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils
import plot_utils


# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

# constants
INDICES = ["ftp-*", "telnet-*"]
SEP = CONFIG["IO"]["CSV_SEP"]
MOST_COMMON_ROCKYOU = 20

# artifacts
BASE_DIR = Path(CONFIG["ARTIFACT_DIR"]) / "ftp-telnet"
DATA_DIR = BASE_DIR / "es"
PLOTS_DIR = BASE_DIR / "plots"
FTP_BOT_IPS = DATA_DIR / "ftp_bot_ips.txt"
TELNET_BOT_IPS = DATA_DIR / "telnet_bot_ips.txt"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

FTP_DF = DATA_DIR / "ftp.csv"
TELNET_DF = DATA_DIR / "telnet.csv"

ROCKYOU_FILE = BASE_DIR / "rockyou.txt.gz"


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


# %%
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
        # lines = [line.rstrip() for line in f.readlines()]
        LOGGER.info(f"Loaded the top {MOST_COMMON_ROCKYOU} ROCKYOU passwords.")
        return pd.Series(lines, dtype="string")


def filter_same_creds(filtered, placebo):
    filter_up = filtered.groupby(["user", "password"]).sum().reset_index()[["user", "password"]]
    placebo_up = placebo.groupby(["user", "password"]).sum().reset_index()[["user", "password"]]
    common = filter_up.merge(placebo_up, on=["user", "password"], how="inner")
    placebo_creds = filtered[
        (filtered.user.isin(common.user)) & (filtered.password.isin(common.password))
    ]
    nonplacebo_creds = filtered[
        (~filtered.user.isin(common.user)) | (~filtered.password.isin(common.password))
    ]
    nonplacebo_creds = nonplacebo_creds[~nonplacebo_creds["client_ip"].isin(placebo_creds["client_ip"])]
    return nonplacebo_creds, placebo_creds


def filter_rockyou_passwords(df, rockyou):
    non_rockyou_rows = df[~df["password"].isin(rockyou)]
    rockyou_rows = df[df["password"].isin(rockyou)]
    non_rockyou_rows = non_rockyou_rows[~non_rockyou_rows["client_ip"].isin(rockyou_rows["client_ip"])]
    return non_rockyou_rows, rockyou_rows


def filter_domain_pw(df):
    def _check_domain_pw(row):
        # return row.domain in row.password
        domain_parts = row.domain.split("-")[:-1]   # don't want TLD
        domain_pw = [row.password.find(part) for part in domain_parts]
        domain_pw = [0 if val == -1 else 1 for val in domain_pw]
        return sum(domain_pw)
    df["domain_pw"] = df.apply(_check_domain_pw, axis=1)
    # nondomain_pw_rows = df[df["domain_pw"] == False]
    # domain_pw_rows = df[df["domain_pw"] == True]
    nondomain_pw_rows = df[df["domain_pw"] == 0]
    domain_pw_rows = df[df["domain_pw"] > 0]
    nondomain_pw_rows = nondomain_pw_rows[~nondomain_pw_rows["client_ip"].isin(domain_pw_rows["client_ip"])]
    return nondomain_pw_rows, domain_pw_rows


def filter_df(df, rockyou, placebos, other_bot_ips):
    placebo_df, nonplacebo_df, _, _ = es_utils.filter_placebo_ips(df)
    nonplacebo_ips = nonplacebo_df[~nonplacebo_df["client_ip"].isin(placebos)]
    nonplacebo_bot_ips = nonplacebo_df[nonplacebo_df["client_ip"].isin(placebos)]

    filtered_2 = nonplacebo_ips

    filtered_3, placebo_creds = filter_same_creds(filtered_2, placebo_df)
    filtered_4, rockyou_rows = filter_rockyou_passwords(filtered_3, rockyou)
    filtered_5, domain_pw_rows = filter_domain_pw(filtered_4)
    filtered_6 = filtered_5[~filtered_5["client_ip"].isin(other_bot_ips)]
    other_bot_ip_rows = filtered_5[filtered_5["client_ip"].isin(other_bot_ips)]

    filter_lvl_dfs = [filtered_6, other_bot_ip_rows, domain_pw_rows, rockyou_rows, placebo_creds, nonplacebo_bot_ips, placebo_df]
    labels = [
        "Unique Client IPs", "Filtered by other services' bot IPs", 
        "Filtered by exact domain in passwords", f"Filtered by top {MOST_COMMON_ROCKYOU} rockyou passwords", 
        "Filtered by exact placebo credentials", "Filtered by placebo IPs", "Filtered by placebo domains"
    ]

    return filter_lvl_dfs, labels

# %%

def run_pipeline(idx_ptrn):
    # get source DF
    source_path = FTP_DF if idx_ptrn == "ftp-*" else TELNET_DF    
    usecols = ["id", "client_ip", "user", "password"]
    dtype = {"id": "uint16", "client_ip": "string", "user": "string", "password": "string"}
    df = es_utils.load_source_df(idx_ptrn, source_path, usecols, dtype, get_ftp_telnet_reqs)

    # get placebo IPs
    all_srvc_unique_ips = es_utils.get_srvc_unique_ips(es_utils.ALL_SRVC_UNIQUE_IPS_DF, filter_time=False)
    placebos, _, _, _ = es_utils.filter_placebo_ips(all_srvc_unique_ips)
    placebos = placebos.client_ip.unique()
    del all_srvc_unique_ips
    LOGGER.info(f"Loaded placebos {len(placebos)}")

    # get other bot IPs
    other_bot_ips = es_utils.get_other_bot_ips(idx_ptrn)

    # run pipeline
    rockyou = get_rockyou_passwords()
    filter_lvl_dfs, labels = filter_df(df, rockyou, placebos, other_bot_ips)
    LOGGER.info(f"Filtered df.")

    bot_ips_file = FTP_BOT_IPS
    if idx_ptrn == "telnet-*":
        bot_ips_file = TELNET_BOT_IPS
    es_utils.save_bot_ips(filter_lvl_dfs[2:], bot_ips_file)

    srvc = idx_ptrn[:idx_ptrn.index("-*")]
    tmp = plot_utils.plot_ip_counts(filter_lvl_dfs, legend=labels, _file=PLOTS_DIR / f"{srvc}-filter-bars.png")

    plot_utils.plot_sankey_filters(tmp, labels, 
        node_labels=["F0", "Placebo Servers", "F1", "Placebo IPs", 
        "F2", "Exact Placebo Credentials", "F3", 
        f"Top {MOST_COMMON_ROCKYOU} ROCKYOU Passwords", "F4", "Exact Domain in Password", "F5", "Other Services' Bot IPs", "F6"],
        _file=PLOTS_DIR / f"{srvc}-sankey.html")
    return tmp


# %%
idx_ptrn = "ftp-*"
ftp_tmp = run_pipeline(idx_ptrn)

# %%
idx_ptrn = "telnet-*"
telnet_tmp = run_pipeline(idx_ptrn)

# %%
