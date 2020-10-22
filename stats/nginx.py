# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
# from IPython import get_ipython

# %%
# get_ipython().run_line_magic("load_ext", "autotime")

# %%
from collections import defaultdict
import json
import logging
from pathlib import Path
import pdb

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, A, Q
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils

# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
INDEX = "nginx-access-*"

# constants
SEP = CONFIG["IO"]["CSV_SEP"]

# artifacts
BASE_DIR = Path(CONFIG["ARTIFACT_DIR"]) / "nginx"
DATA_DIR = BASE_DIR / "es"
PLOTS_DIR = BASE_DIR / "plots"
NGINX_IP_PATHS_DF = DATA_DIR / "nginx_ip_paths.csv"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# globals
LOGGER = utils.get_logger("nginx_stats", BASE_DIR / "nginx.log", logging.INFO)


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
def get_nginx_reqs(csv):
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
    source_aggs_map = {INDEX: source_aggs}
    cols = ["id", "client_ip", "path", "count"]
    df = es_utils.query_scan_idx_aggs(
        csv, source_aggs_map, [INDEX], _process_bucket, cols, filter_time=True
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

df = get_nginx_reqs(NGINX_IP_PATHS_DF)


# %%
df["path_len"] = df["path"].apply(lambda x: len(x))
filtered_1_df = df[~df["client_ip"].isin(placebos["client_ip"])].assign(FilterLvl=1.1)
placebo_df = df[df["client_ip"].isin(placebos["client_ip"])]].assign(FilterLvl=1.2)

tmp = pd.concat([filtered_1_df, placebo_df])
tmp = pd.melt(tmp, id_vars=["FilterLvl"], var_name=["Filter Level"], value_vars=["path_len"])
ax = sns.boxplot(x="FilterLvl", y="value", hue="Filter Level", data=tmp)
plt.title("Request Path Length Distribution")
plt.savefig(PLOTS_DIR / "path_length_boxplot.png")

# 30467
# 33710