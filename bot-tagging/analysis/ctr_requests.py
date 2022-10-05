# stdlib
from collections import defaultdict
from datetime import datetime
from os import setpgrp
from pathlib import Path
import re
from urllib.parse import urlparse
import pdb

# 3p
from elasticsearch.exceptions import RequestError
from elasticsearch_dsl import A, Q
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# proj
from enums import QueryEnum
import utils
import es_utils
import plot_utils as p_utils


###############################################################################


LOGGER = utils.get_logger("analysis")
RES_DIR = Path("./analysis/ctr_reqs")
PLOTS_DIR = Path("./plots/ctr_reqs")
RES_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in NONPLACEBOS]
SORTED_CTRS = utils.get_sorted_containers()
DEFAULT_TOP_N = 25

LOG_PROGRESS = {"nginx-access-*": 10_000}

IDX_PTRN = "nginx-access-*"
SHARD_SIZE = 500_000

SEP = "|<>|"


def _get_sig_text_path(idx_ptrn, ctid, data, shard_size=SHARD_SIZE, n=DEFAULT_TOP_N):
    LOGGER.info(f"  _get_sig_text_path {data} {ctid}")
    if not data.exists():
        cols = ["ctid", "text", "doc_count_1", "bg_count_1", "score", "doc_count_2", "bg_count_2"]
        search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[ctid])
        search.query.must_not.append(Q("term", nginx__path__keyword="/"))
        sample_agg = A(
            "diversified_sampler", max_docs_per_value=3, shard_size=shard_size, field="ip.keyword"
        )
        sig_agg = A("significant_text", field="nginx.path", size=n)
        search.aggs.bucket("my_sample", sample_agg).bucket("sig_text", sig_agg)
        res = search.execute()
        LOGGER.debug(f"    {ctid} took {res.took} ms")
        sig_text = res.aggs.my_sample.sig_text
        doc_count_2 = str(sig_text.doc_count)
        bg_count_2 = str(sig_text.bg_count)
        with open(data, "w+") as f:
            f.write(f"{','.join(cols)}\n")
            for bucket in sig_text.buckets:
                text = bucket.key
                doc_count_1 = str(bucket.doc_count)
                bg_count_1 = str(bucket.bg_count)
                score = str(bucket.score)
                row = [ctid, text, doc_count_1, bg_count_1, score, doc_count_2, bg_count_2]
                f.write(f"{','.join(row)}\n")
    dtype = {
        "ctid": "category",
        "text": "string",
        "doc_count_1": "int64",
        "doc_count_2": "int64",
        "bg_count_1": "int64",
        "bg_count_2": "int64",
        "score": "float64",
    }
    df = pd.read_csv(data, header=0)
    df = df.astype(dtype)
    return df


def _get_path_breakdown(
    idx_ptrn,
    ctid,
    data,
    keywords,
    shard_size=SHARD_SIZE,
    n_paths=1000,
    n_query=10,
):
    LOGGER.info(f"  _get_path_breakdown {data} {ctid}")
    if not data.exists():
        paths_count = defaultdict(int)
        path_query_count = defaultdict(lambda: defaultdict(int))
        search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[ctid])
        q = Q(
            "bool",
            should=[Q("match", nginx__path=text) for text in keywords],
            must_not=[Q("term", nginx__path__keyword="/")],
            minimum_should_match=1,
        )
        search = search.query(q)
        sample_agg = A(
            "diversified_sampler", max_docs_per_value=3, shard_size=shard_size, field="ip.keyword"
        )
        path_agg = A("terms", field="nginx.path.keyword", size=n_paths)
        search.aggs.bucket("my_sample", sample_agg).bucket("paths", path_agg)
        res = search.execute()
        LOGGER.debug(f"    {ctid} took {res.took} ms")
        paths = res.aggs.my_sample.paths
        for bucket in paths.buckets:
            path = bucket.key
            doc_count = bucket.doc_count
            o = urlparse(path)
            paths_count[o.path] += doc_count
            for kv in o.query.split("&"):
                if len(kv) == 0:
                    continue
                key = kv.split("=")[0] if "=" in kv else kv
                path_query_count[o.path][key] += doc_count
        cols = ["ctid", "path", "path_count", "top_query"]
        with open(data, "w+") as f:
            f.write(f"{SEP.join(cols)}\n")
            for path, path_count in paths_count.items():
                query_count = path_query_count[path]
                top_q_count = dict(
                    sorted(query_count.items(), key=lambda x: x[1], reverse=True)[:n_query]
                )
                row = [ctid, path, path_count, top_q_count]
                row = [str(x) for x in row]
                f.write(f"{SEP.join(row)}\n")
    dtype = {"ctid": "category", "path": "string", "path_count": "int64", "top_query": "object"}
    df = pd.read_csv(data, header=0, sep=re.escape(SEP))
    df = df.astype(dtype)
    df.top_query = df.top_query.apply(lambda x: eval(x))
    return df


# def _get_popular_ctr_reqs(idx_ptrn, ctid, filename):
#     LOGGER.info(f"_get_popular_ctr_reqs {filename} {ctid}")
#     data = TMP_DIR / filename
#     if data.exists():
#         pass
#     else:
#         # cols = ["ctid", "path", "ip", "method", "num_reqs"]
#         cols = ["ctid", "path", "num_reqs"]
#         search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=[ctid])
#         aggs = [
#             {"path": A("terms", field="nginx.path.keyword")},
#             # {"ip": A("terms", field="ip.keyword")},
#             # {"method": A("terms", field="nginx.method.keyword")},
#         ]
#         _generator = es_utils.scan_aggs(search, aggs, size=1000)
#         with open(data, "w+") as f:
#             f.write(f"{','.join(cols)}\n")
#             for idx, bucket in enumerate(_generator):
#                 if idx % LOG_PROGRESS[idx_ptrn] == 0:
#                     LOGGER.debug(f"  on bucket {idx}...")
#                 path = bucket.key.path
#                 # ip = bucket.key.ip
#                 # method = bucket.key.method
#                 # if not utils.validate_ip(bucket.ip):
#                 #     continue
#                 # row = [ctid, path, ip, method, bucket.doc_count]
#                 row = [ctid, path, str(bucket.doc_count)]
#                 f.write(f"{','.join(row)}\n")
#     # dtype = {"ctid": "category", "path": "string", "ip": "string", "method": "category", "num_reqs": "int64"}
#     dtype = {"ctid": "category", "path": "string", "num_reqs": "int64"}
#     df = pd.read_csv(data, header=0)
#     df = df.astype(dtype)
#     df = df.sort_values(by=["num_reqs"], ascending=False)
#     return df


# def _get_path_breakdown(df, filename):
#     LOGGER.info(f"_get_path_breakdown")
#     data = RES_DIR / filename
#     if data.exists():
#         paths = pd.read_csv(data)
#     else:
#         path_ips = defaultdict(lambda: defaultdict(list))
#         for row in df.itertuples():
#             path_ips[row.path]["ips"].append(row.ip)
#             path_ips[row.path]["ctids"].append(row.ctid)
#             path_ips[row.path]["methods"].append(row.method)
#         rows = []
#         for path, _dict in path_ips.items():
#             ips = _dict["ips"]
#             ctids = _dict["ctids"]
#             methods = _dict["methods"]
#             frac_get = methods.count("GET") / len(methods)
#             frac_post = methods.count("POST") / len(methods)
#             row = [
#                 path,
#                 len(set(ips)),
#                 len(ips),
#                 len(set(ctids)),
#                 frac_get,
#                 frac_post,
#                 set(methods),
#                 set(ips),
#                 set(ctids),
#             ]
#             rows.append(row)
#         paths = pd.DataFrame(
#             rows,
#             columns=[
#                 "path",
#                 "unique_ips",
#                 "num_req_ips",
#                 "unique_ctids",
#                 "frac_get",
#                 "frac_post",
#                 "methods",
#                 "ips",
#                 "ctids",
#             ],
#         )
#     dtype = {
#         "path": "string",
#         "unique_ips": "int64",
#         "num_req_ips": "int64",
#         "unique_ctids": "int64",
#         "frac_get": "float32",
#         "frac_post": "float32",
#     }
#     paths = paths.astype(dtype)
#     return paths


def get_top_reqs_nonplacebos(idx_ptrn):
    def _get_sig_paths_ctr(idx_ptrn, ctid):
        srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
        data = RES_DIR / f"{srvc}-{ctid}-sig_text.csv"
        df = _get_sig_text_path(idx_ptrn, str(ctid), data)
        return df

    def _get_path_breakdown_ctr(idx_ptrn, ctid, df):
        keywords = df[df.ctid == ctid].text
        data = RES_DIR / f"{srvc}-{ctid}-paths.csv"
        return _get_path_breakdown(idx_ptrn, ctid, data, keywords)

    srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
    sig_text_data = RES_DIR / f"{srvc}-nonplacebos-sig_text.csv"
    ctids = list(SORTED_CTRS)
    ctids = [ctid for ctid in ctids if int(ctid) in NONPLACEBOS]
    # ctids = [657]
    LOGGER.info(f"get_top_reqs_nonplacebos {idx_ptrn}")
    if not sig_text_data.exists():
        LOGGER.info(f"  not found: {sig_text_data}")
        dfs_1 = {ctid: _get_sig_paths_ctr(idx_ptrn, ctid) for ctid in ctids}
        sig_text_df = dfs_1[ctids[0]]
        for ctid in ctids[1:]:
            ctid_df = dfs_1[ctid]
            sig_text_df = sig_text_df.append(ctid_df)
        del dfs_1
        sig_text_df.to_csv(sig_text_data, index=False, header=True)
    else:
        LOGGER.info(f"  loaded {sig_text_data}")
        sig_text_df = pd.read_csv(sig_text_data, header=0)
    dtype = {
        "ctid": "category",
        "text": "string",
        "doc_count_1": "int64",
        "doc_count_2": "int64",
        "bg_count_1": "int64",
        "bg_count_2": "int64",
        "score": "float64",
    }
    sig_text_df = sig_text_df.astype(dtype)
    path_data = RES_DIR / f"{srvc}-nonplacebos-paths.csv"
    if not path_data.exists():
        LOGGER.info(f"  not found: {path_data}")
        dfs_2 = {ctid: _get_path_breakdown_ctr(idx_ptrn, ctid, sig_text_df) for ctid in ctids}
        paths_df = dfs_2[ctids[0]]
        for ctid in ctids[1:]:
            ctid_df = dfs_2[ctid]
            paths_df = paths_df.append(ctid_df)
        del dfs_2
        paths_df.to_csv(path_data, index=False, header=True, sep=SEP)
    else:
        LOGGER.info(f"  loaded {path_data}")
        paths_df = pd.read_csv(path_data, header=0, sep=re.escape(SEP))
    dtype = {"ctid": "category", "path": "string", "path_count": "int64", "top_query": "object"}
    paths_df = paths_df.astype(dtype)
    paths_df.top_query = paths_df.top_query.apply(lambda x: eval(x))


def check_657_announce_ips(idx_ptrn):
    search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=["657"])
    announce_path_q = Q("wildcard", nginx__path__keyword={"value": "/announce*"})
    search = search.query(announce_path_q)
    ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
    announce_ips = es_utils.scan_aggs(search, [ip_agg], size=1_000)
    batch_size = 100
    for idx, bucket in enumerate(announce_ips):
        if idx % 100_000 == 0:
            LOGGER.debug(f"  on ip {idx}...")
        ip = bucket.key.ip
        if not utils.validate_ip(ip):
            continue
        raise NotImplementedError()


###############################################################################

# FUNCS = [get_asn_distribution, get_top_n_asn_placebos, get_top_n_asn_nonplacebos]
FUNCS = [get_top_reqs_nonplacebos]


def analyze(idx_ptrn):
    if idx_ptrn != IDX_PTRN:
        raise NotImplementedError()
    for func in FUNCS:
        func(IDX_PTRN)
