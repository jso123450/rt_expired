# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from IPython import get_ipython

# %%
get_ipython().run_line_magic("load_ext", "autotime")

# %%
import logging
from pathlib import Path
import pdb
import re

from elasticsearch_dsl import A
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils
import plot_utils

# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
INDEX = "nginx-access-*"

# constants
SEP = CONFIG["IO"]["CSV_SEP"]
TRAP_PATH = "/trap/"
ILLEGAL_URL_CHARS = [" ", "|", '"', "<", ">", "^", "`", "{", "}", "~"]
ILLEGAL_URL_REGEX = "|".join(map(re.escape, ILLEGAL_URL_CHARS))

# artifacts
ARTIFACT_DIR = Path(CONFIG["ARTIFACT_DIR"]) / "nginx"
HOME_DIR = Path(CONFIG["HOME_DIR"])
DATA_DIR = ARTIFACT_DIR / "es"
PLOTS_DIR = ARTIFACT_DIR / "plots"
NGINX_IP_PATHS_DF = DATA_DIR / "nginx_ip_paths_nonplacebos.csv"
BOT_IPS_FILE = DATA_DIR / "nginx_bot_ips.txt"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# globals
LOGGER = utils.get_logger("nginx_stats", ARTIFACT_DIR / "nginx.log", logging.INFO)


# %%
def get_nginx_reqs(idx_ptrn, csv):
    def _process_bucket(bucket):
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        path = bucket.key.path
        ip, domain = es_utils.get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:  # test container
            return
        
        row = [ctid, client_ip, path, str(bucket.doc_count)]
        output = f"{SEP.join(row)}\n"
        return output

    source_aggs = [
        {"ctid": A("terms", field="container.id.keyword")},
        {"ip": A("terms", field=es_utils.get_ip_field(INDEX))},
        {"path": A("terms", field="nginx.access.url.keyword")},
    ]
    source_aggs_map = {idx_ptrn: source_aggs}
    cols = ["id", "client_ip", "path", "count"]
    nonplacebos = sorted(list(NONPLACEBOS.keys()))
    nonplacebos = [str(_id) for _id in nonplacebos]
    df = es_utils.query_scan_idx_aggs(
        csv, source_aggs_map, [idx_ptrn], _process_bucket, cols, filter_time=True, ctids=nonplacebos
    )
    df = df.astype(
        {
            "id": "string",
            "client_ip": "string",
            "path": "string",
            "count": "int64",
        }
    )
    return df

# %%
def filter_illegal_tokens(df):
    illegal_tokens = df[df.path.str.contains(ILLEGAL_URL_REGEX)]
    non_illegal_tokens = df[~df.path.str.contains(ILLEGAL_URL_REGEX)]
    return non_illegal_tokens, illegal_tokens


def filter_df(df, placebo_ips, idx_placebos, other_bot_ips):
    nonplacebo_ips = df[~df["client_ip"].isin(placebo_ips)]
    nonplacebo_bot_ips = df[df["client_ip"].isin(placebo_ips)]

    filtered_2 = nonplacebo_ips # requests with IPs not found contacting placebos

    trap_df = filtered_2[filtered_2["path"].str.find(TRAP_PATH) > -1] # requests that accessed a trap path
    filtered_3 = filtered_2[filtered_2["path"].str.find(TRAP_PATH) == -1]  # requests that did not access a trap path
    filtered_3 = filtered_3[~filtered_3["client_ip"].isin(trap_df.client_ip.unique())]  # filter out requests from IPs that accessed traps
    filtered_4, illegal_token_rows = filter_illegal_tokens(filtered_3)
    
    filtered_5 = filtered_4[~filtered_4["client_ip"].isin(other_bot_ips)]
    other_bot_ip_rows = filtered_4[filtered_4["client_ip"].isin(other_bot_ips)]

    filter_lvl_dfs = [filtered_5, other_bot_ip_rows, illegal_token_rows, trap_df, nonplacebo_bot_ips, idx_placebos]
    labels = [
        "Unique Client IPs", "Filtered by other services' bot IPs", 
        "Filtered by illegal URL characters", "Filtered by trap paths", 
        "Filtered by placebo IPs", "Filtered by placebo domain"
    ]

    return filter_lvl_dfs, labels

# %%
# df["path_len"] = df["path"].apply(lambda x: len(x))


# tmp = pd.concat([filtered_1_df, placebo_df])
# tmp = pd.melt(tmp, id_vars=["FilterLvl"], var_name=["Filter Level"], value_vars=["path_len"])
# ax = sns.boxplot(x="FilterLvl", y="value", hue="Filter Level", data=tmp)
# plt.title("Request Path Length Distribution")
# plt.savefig(PLOTS_DIR / "path_length_boxplot.png")

# # 30467
# # 33710

# %%
def run_pipeline():
    # get source df
    usecols = ["id", "client_ip", "path"]
    dtype = {"id": "uint16", "client_ip": "string", "path": "string"}
    df = es_utils.load_source_df(INDEX, NGINX_IP_PATHS_DF, usecols, dtype, get_nginx_reqs)

    # get placebo IPs
    all_srvc_unique_ips = es_utils.get_srvc_unique_ips(es_utils.ALL_SRVC_UNIQUE_IPS_DF, filter_time=False)
    placebos, _, _, _ = es_utils.filter_placebo_ips(all_srvc_unique_ips)
    placebo_ips = placebos.client_ip.unique()
    idx_placebos = placebos[placebos.idx_ptrn==INDEX]
    del all_srvc_unique_ips
    del placebos

    LOGGER.info(f"Loaded placebo IPs {len(placebo_ips)}")

    # get other bot IPs
    other_bot_ips = es_utils.get_other_bot_ips(INDEX)

    # run pipeline
    filter_lvl_dfs, labels = filter_df(df, placebo_ips, idx_placebos, other_bot_ips)
    LOGGER.info(f"Filtered df.")

    ## filter_lvl_dfs = [final, filtered_from_other_idx, ...]
    es_utils.save_bot_ips(filter_lvl_dfs[2:], BOT_IPS_FILE)

    srvc = "nginx"
    tmp = plot_utils.plot_ip_counts(filter_lvl_dfs, legend=labels, _file=PLOTS_DIR / f"{srvc}-filter-bars.png")
    plot_utils.plot_sankey_filters(tmp, labels, 
        node_labels=[
            "F0", "Placebo Servers", 
            "F1", "Placebo IPs", 
            "F2", "Bot Trap Paths", 
            "F3", "Illegal URL Chars", 
            "F4", "Other Services' Bot IPs", "F5"
        ],
        _file=PLOTS_DIR / f"{srvc}-sankey.html")
    return tmp

# %%
tmp = run_pipeline()

# %%
