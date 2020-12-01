# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from IPython import get_ipython
get_ipython().run_line_magic("load_ext", "autotime")

# %%
from collections import defaultdict
import gzip
import logging
from pathlib import Path
import pdb

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
FILTERED_DIR = BASE_DIR / "filtered"
FTP_BOT_IPS = DATA_DIR / "ftp_bot_ips.txt"
TELNET_BOT_IPS = DATA_DIR / "telnet_bot_ips.txt"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
FILTERED_DIR.mkdir(parents=True, exist_ok=True)

FTP_DF = DATA_DIR / "ftp.csv"
TELNET_DF = DATA_DIR / "telnet.csv"

ROCKYOU_FILE = BASE_DIR / "rockyou.txt.gz"


# globals
LOGGER = utils.get_logger("ftp-telnet_stats", BASE_DIR / "ftp-telnet.log", logging.INFO)


# %%
def get_ftp_telnet_reqs(idx_ptrn, csv):
    def _process_bucket(idx_ptrn, bucket):
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
    # params
    usecols = ["id", "client_ip", "user", "password"]
    dtype = {"id": "uint16", "client_ip": "string", "user": "string", "password": "string"}
    srvc = idx_ptrn[:idx_ptrn.index("-*")]
    source_aggs = [
        {"ctid": A("terms", field="container.id.keyword")},
        {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))},
        {"user": A("terms", field=f"{srvc}.user.keyword")},
        {"password": A("terms", field=f"{srvc}.password.keyword")}
    ]
    source_aggs_map = {idx_ptrn: source_aggs}
    cols = ["id", "client_ip", "user", "password", "count"]    
    nonplacebos = sorted(list(NONPLACEBOS.keys()))
    nonplacebos = [str(_id) for _id in nonplacebos]

    # load df
    df = es_utils.query_scan_idx(
        csv,
        [idx_ptrn],
        _process_bucket,
        cols,
        usecols,
        dtype,
        source_aggs_map=source_aggs_map,
        filter_time=True,
        ctids=None,
    )
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

    filtered_3, rockyou_rows = filter_rockyou_passwords(filtered_2, rockyou)
    filtered_4, domain_pw_rows = filter_domain_pw(filtered_3)
    filtered_5, placebo_creds = filter_same_creds(filtered_4, placebo_df)
    filtered_6 = filtered_5[~filtered_4["client_ip"].isin(other_bot_ips)]
    other_bot_ip_rows = filtered_5[filtered_4["client_ip"].isin(other_bot_ips)]

    filter_lvl_dfs = [filtered_6, other_bot_ip_rows, placebo_creds, domain_pw_rows, rockyou_rows, nonplacebo_bot_ips, placebo_df]
    labels = [
        "Unique Client IPs", 
        "Filtered by other services' bot IPs", 
        "Filtered by exact placebo credentials", 
        "Filtered by exact domain in passwords", 
        f"Filtered by top {MOST_COMMON_ROCKYOU} rockyou passwords", 
        "Filtered by placebo IPs",
        "Filtered by placebo domains"
    ]

    return filter_lvl_dfs, labels

# %%

def bot_filter_pipeline(idx_ptrn):
    # get source df
    source_path = FTP_DF if idx_ptrn == "ftp-*" else TELNET_DF
    df = get_ftp_telnet_reqs(idx_ptrn, source_path)

    # get placebo IPs
    placebos = sorted(list(PLACEBOS.keys()))
    placebos = [str(_id) for _id in placebos]
    placebo_srvc_unique_ips = es_utils.get_srvc_unique_ips(
        es_utils.PLACEBO_SRVC_UNIQUE_IPS_DF, ctids=placebos, filter_time=False
    )
    placebo_ips = placebo_srvc_unique_ips.client_ip.unique()
    ## don't need this since ftp and telnet have both placebo & nonplacebo for now
    # idx_placebos = placebo_srvc_unique_ips[placebo_srvc_unique_ips.idx_ptrn==idx_ptrn]
    del placebo_srvc_unique_ips
    del placebos
    LOGGER.info(f"Loaded placebos {len(placebo_ips)}")

    # get other bot IPs
    other_bot_ips = es_utils.get_other_bot_ips(idx_ptrn)

    # run pipeline
    rockyou = get_rockyou_passwords()
    filter_lvl_dfs, labels = filter_df(df, rockyou, placebo_ips, other_bot_ips)
    LOGGER.info(f"Filtered df.")

    bot_ips_file = FTP_BOT_IPS
    if idx_ptrn == "telnet-*":
        bot_ips_file = TELNET_BOT_IPS
    es_utils.save_bot_ips(filter_lvl_dfs[2:], bot_ips_file)

    srvc = idx_ptrn[:idx_ptrn.index("-*")]
    tmp = plot_utils.plot_ip_counts(filter_lvl_dfs, legend=labels, _file=PLOTS_DIR / f"{srvc}-filter-bars.png")

    plot_utils.plot_sankey_filters(filter_lvl_dfs, 
        node_labels=[
            "F0", "Placebo Servers", 
            "F1", "Placebo IPs", 
            "F2", f"Top {MOST_COMMON_ROCKYOU} ROCKYOU Passwords", 
            "F3", "Exact Domain in Password", 
            "F4", "Exact Placebo Credentials", 
            "F5", "Other Services' Bot IPs", 
            "F6"],
        _file=PLOTS_DIR / f"{srvc}-sankey.html")
    return tmp, filter_lvl_dfs


def get_placebo_creds_breakdown(df):
    up_ips = defaultdict(lambda: defaultdict(list))
    for row in df.itertuples():
        up = (row.user, row.password)
        up_ips[up]["ips"].append(row.client_ip)
        up_ips[up]["ctids"].append(row.id)
    rows = []
    for up, _dict in up_ips.items():
        ips = _dict["ips"]
        ctids = _dict["ctids"]
        row = [
            up[0], up[1], len(set(ips)), len(ips), 
            len(set(ctids)), 
            ips, ctids
        ]
        rows.append(row)
    tmp = pd.DataFrame(rows, columns=[
        "user", "password", "unique_ips", 
        "num_reqs", "unique_ctids", 
        "ips", "ctids"
    ])
    return tmp


def plot_creds_distribution(df, which, num_str, srvc):
    plt.hist(df[which], bins="auto")
    fig = plt.gcf()
    fig.patch.set_facecolor("white")
    plt.yscale("log")
    plt.title(f"Number of {num_str} for Credential Combinations")
    plt.xlabel(f"Number of {num_str}")
    plt.ylabel("Frequency")

    # plt.show()
    plt.savefig(PLOTS_DIR / f"{srvc}-creds-{which}-dist.png")
    plt.clf()

# %%
idx_ptrn = "ftp-*"
ftp_tmp, ftp_filtered = bot_filter_pipeline(idx_ptrn)
ftp_filtered[0].to_csv(FILTERED_DIR / "ftp-filtered.csv", 
    index=False, header=True
)
ftp_placebo_creds = get_placebo_creds_breakdown(ftp_filtered[2])
ftp_placebo_creds.to_csv(FILTERED_DIR / "ftp-placebo-creds.csv", 
    index=False, header=True
)
plot_creds_distribution(ftp_placebo_creds, "num_reqs", "Requests", "ftp")
plot_creds_distribution(ftp_placebo_creds, "unique_ips", "IPs", "ftp")
plot_creds_distribution(ftp_placebo_creds, "unique_ctids", "Containers", "ftp")

# %%
idx_ptrn = "telnet-*"
telnet_tmp, telnet_filtered = bot_filter_pipeline(idx_ptrn)
telnet_filtered[0].to_csv(FILTERED_DIR / "telnet-filtered.csv", 
    index=False, header=True
)
telnet_placebo_creds = get_placebo_creds_breakdown(telnet_filtered[2])
telnet_placebo_creds.to_csv(FILTERED_DIR / "telnet-placebo-creds.csv", 
    index=False, header=True
)
plot_creds_distribution(telnet_placebo_creds, "num_reqs", "Requests", "telnet")
plot_creds_distribution(telnet_placebo_creds, "unique_ips", "IPs", "telnet")
plot_creds_distribution(telnet_placebo_creds, "unique_ctids", "Containers", "telnet")

# %%