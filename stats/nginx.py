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
from elasticsearch_dsl.connections import connections
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils


# %%
connections.configure(default={"hosts": ["130.245.169.240:9200"]})

# files
BASE_DIR = Path("../data/nginx")
DATA_DIR = BASE_DIR / "es"
PLOTS_DIR = BASE_DIR / "plots"
NGINX_IP_PATHS_DF = DATA_DIR / "nginx_ip_paths.csv"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

# from utils
LOGGER = utils.get_logger("nginx_stats", BASE_DIR / "log.log", logging.INFO)
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
INDEX = "nginx-access-*"

# constants

# artifacts


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
nonplacebo_ips = nonplacebos[~nonplacebos["client_ip"].isin(placebos["client_ip"])]
nonplacebo_bot_ips = nonplacebos[nonplacebos["client_ip"].isin(placebos["client_ip"])]
LOGGER.info(f"nonplacebo ips {nonplacebo_ips.shape}, nonplacebo_bot_ips {nonplacebo_bot_ips.shape}")


# %%
def get_nginx_reqs(csv):
    def _process_bucket(idx_ptrn, bucket):
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        path = bucket.key.path
        ip, domain = es_utils.get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:  # test container
            return
        output = f"{ctid}|{domain}|{ip}|{client_ip}|{path}|{bucket.doc_count}\n"
        return output

    source_aggs = [
        {"ctid": A("terms", field="container.id.keyword")},
        {"ip": A("terms", field=es_utils.get_ip_field(INDEX))},
        {"path": A("terms", field="nginx.access.url.keyword")},
    ]
    source_aggs_map = {INDEX: source_aggs}
    cols = ["id", "domain", "ip", "client_ip", "path", "count"]
    df = es_utils.scan_idx_aggs(
        source_aggs_map, [INDEX], _process_bucket, cols, csv, filter_time=True
    )
    df = df.astype(
        {
            "id": "string",
            "domain": "string",
            "ip": "string",
            "client_ip": "string",
            "path": "string",
            "count": "int64",
        }
    )
    return df


get_nginx_reqs(NGINX_IP_PATHS_DF)