from collections import defaultdict
import json
from pathlib import Path
import re
import pdb

from elasticsearch_dsl import Search, A
import pandas as pd
import numpy as np

import utils

# from utils
LOGGER = utils.get_logger("es_utils", "./es_utils.log")
CONFIG = utils.get_config()
SEP = CONFIG["IO"]["CSV_SEP"]
CHUNKSIZE = CONFIG["IO"]["CHUNK_SIZE"]
CTRS = utils.get_containers()
TIME_FMT = CONFIG["TIME"]["FMT"]

# constants
INDICES_IP_MAPPING = {
    "nginx-access-*": "nginx.access.remote_ip.keyword",
    "postfix-smtpd-*": "postfix_client_ip.keyword",
    "telnet-*": "telnet.ip.keyword",
    "ftp-*": "ftp.ip.keyword",
    # "nginx-access-*": "ip.keyword",
    # "postfix-*": "postfix_client_ip.keyword",
    # "telnet-*": "ip.keyword",
    # "ftp-*": "ip.keyword",
    # "ssh-*": "ssh.ip.keyword",
}

ALL_SRVC_UNIQUE_IPS_DF = Path(CONFIG["ARTIFACT_DIR"]) / "all_srvc_unique_ips.csv"
FILTERED_SRVC_UNIQUE_IPS_DF = Path(CONFIG["ARTIFACT_DIR"]) / "filtered_srvc_unique_ips.csv"
PLACEBO_SRVC_UNIQUE_IPS_DF = Path(CONFIG["ARTIFACT_DIR"]) / "placebo_srvc_unique_ips.csv"
BOT_IPS_MAPPING = {
    "nginx-access-*": Path(CONFIG["ARTIFACT_DIR"]) / "nginx" / "es" / "nginx_bot_ips.txt",
    "ftp-*": Path(CONFIG["ARTIFACT_DIR"]) / "ftp-telnet" / "es" / "ftp_bot_ips.txt",
    "telnet-*": Path(CONFIG["ARTIFACT_DIR"]) / "ftp-telnet" / "es" / "telnet_bot_ips.txt",
}
# PLACEBO_IPS_MAPPING = {
#     "nginx-access-*": Path(CONFIG["ARTIFACT_DIR"]) / "placebos-nginx.csv",
#     "postfix-*": Path(CONFIG["ARTIFACT_DIR"]) / "placebos-postfix.csv",
#     "telnet-*": Path(CONFIG["ARTIFACT_DIR"]) / "placebos-telnet.csv",
#     "ftp-*": Path(CONFIG["ARTIFACT_DIR"]) / "placebos-ftp.csv",
#     "ssh-*": Path(CONFIG["ARTIFACT_DIR"]) / "placebos-ssh.csv"
# }
CONST_LOG_EVERY_N = 100_000


# def get_field(hit, traversal):
#     field = hit
#     for key in traversal:
#         if field == None:
#             break
#         field = field.get(key, None)
#     return field if field != hit else None


############################################################################################


def scan_aggs(search, source_aggs, inner_aggs={}, size=10):
    """
    Helper function used to iterate over all possible bucket combinations of
    ``source_aggs``, returning results of ``inner_aggs`` for each. Uses the
    ``composite`` aggregation under the hood to perform this.
    """

    def run_search(**kwargs):
        s = search[:0]
        s.aggs.bucket("comp", "composite", sources=source_aggs, size=size, **kwargs)
        for agg_name, agg in inner_aggs.items():
            s.aggs["comp"][agg_name] = agg
        return s.execute()

    response = run_search()
    while response.aggregations.comp.buckets:
        for b in response.aggregations.comp.buckets:
            yield b
        if "after_key" in response.aggregations.comp:
            after = response.aggregations.comp.after_key
        else:
            after = response.aggregations.comp.buckets[-1].key
        response = run_search(after=after)


def init_search(idx_ptrn, filter_time, ctids, windows, time_fmt, sort_timestamp):
    s = Search(index=idx_ptrn)
    if filter_time:
        idx_windows = windows.get(idx_ptrn, windows["DEFAULT"])
        start_window = idx_windows["START"]
        end_window = idx_windows["END"]
        s = s.filter(
            "range",
            **{"@timestamp": {"gte": start_window, "lt": end_window, "format": time_fmt}},
        )
    if ctids is not None:
        s = s.query(
            "terms_set",
            container__id={"terms": ctids, "minimum_should_match_script": {"source": "1"}},
        )
        # s = s.query("terms_set", log__container={"terms": ctids, "minimum_should_match_script": {"source": "1"}})
    if sort_timestamp:
        s = s.sort({"container.id.keyword": {"order": "asc"}}, {"@timestamp": {"order": "asc"}})
        # s = s.sort({"log.container.keyword": {"order": "asc"}}, {"@timestamp": {"order": "asc"}})
    return s


############################################################################################


def _scan_idx(
    csv,
    indices,
    process,  # outputs row for file
    cols,
    source_aggs_map=None,
    filter_time=False,
    ctids=None,
    windows=CONFIG["TIME"]["WINDOWS"],
    time_fmt=TIME_FMT,
    sort_timestamp=False,
    sep=SEP,
):
    _file = open(csv, "w+")
    cols_str = sep.join(cols)
    _file.write(f"{cols_str}\n")
    try:
        for idx, idx_ptrn in enumerate(indices):
            LOGGER.info(f"Processing {idx_ptrn}...{len(indices)-idx-1} left")
            search = init_search(idx_ptrn, filter_time, ctids, windows, time_fmt, sort_timestamp)
            pdb.set_trace()
            _generator = None
            if source_aggs_map is not None:
                _generator = scan_aggs(search, source_aggs_map[idx_ptrn], size=1_000)
            else:
                if sort_timestamp:
                    search = search.params(size=1_000, preserve_order=True)
                else:
                    search = search.params(size=1_000)
                _generator = search.scan()
            LOGGER.info(search.to_dict())
            # pdb.set_trace()
            for idx, obj in enumerate(_generator):
                if idx % CONST_LOG_EVERY_N == 0:
                    LOGGER.info(f"  at obj {idx}...")
                row = process(obj, idx_ptrn=idx_ptrn)
                if row is not None:
                    _file.write(row)
            LOGGER.info(f"Finished {idx_ptrn}...")
    finally:
        _file.close()


def query_scan_idx(
    csv,
    indices,
    process,
    cols,
    usecols,
    dtype,
    source_aggs_map=None,
    filter_time=False,
    ctids=None,
    windows=CONFIG["TIME"]["WINDOWS"],
    time_fmt=TIME_FMT,
    sort_timestamp=False,
    date_cols=[],
    sep=SEP,
):
    df = None
    exists = csv.exists()
    if not exists:
        LOGGER.info(f"{csv} not found, fetching...")
        _scan_idx(
            csv,
            indices,
            process,
            cols,
            source_aggs_map=source_aggs_map,
            filter_time=filter_time,
            ctids=ctids,
            windows=windows,
            time_fmt=time_fmt,
            sort_timestamp=sort_timestamp,
            sep=sep,
        )
    LOGGER.info(f"Loading from {csv}.")
    df = pd.read_csv(
        csv,
        header=0,
        sep=re.escape(sep),
        usecols=usecols,
        dtype=dtype,
        parse_dates=date_cols,
        date_parser=pd.to_datetime,
    )
    df = add_ip_domain_cols(df, CTRS)
    return df


def get_srvc_unique_ips(csv, ctids=None, filter_time=False):
    def _process_bucket(bucket, **kwargs):
        idx_ptrn = kwargs["idx_ptrn"]
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        ip, domain = get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:
            return None
        row = [ctid, idx_ptrn, client_ip, str(bucket.doc_count)]
        output = f"{'|'.join(row)}\n"
        return output

    source_aggs = [{"ctid": A("terms", field="container.id.keyword")}]
    # source_aggs = [{"ctid": A("terms", field="log.container.keyword")}]
    source_aggs_map = {}
    for idx_ptrn in INDICES_IP_MAPPING:
        ip_agg = {"ip": A("terms", field=get_ip_field(idx_ptrn))}
        idx_aggs = list(source_aggs)
        idx_aggs.append(ip_agg)
        source_aggs_map[idx_ptrn] = idx_aggs
    cols = ["id", "idx_ptrn", "client_ip", "count"]
    usecols = ["id", "idx_ptrn", "client_ip"]
    dtype = {
        "id": "uint16",
        "idx_ptrn": "string",
        "client_ip": "string",
    }
    df = query_scan_idx(
        csv,
        INDICES_IP_MAPPING,
        _process_bucket,
        cols,
        usecols,
        dtype,
        source_aggs_map=source_aggs_map,
        filter_time=filter_time,
        ctids=ctids,
        sep="|",
    )
    return df


############################################################################################


def get_ip_domain(ctid, ctrs):
    try:
        ip = ctrs[int(ctid)]["ip"]
        domain = ctrs[int(ctid)]["domain"]
        return ip, domain
    except KeyError:  # test container
        return None, None


def add_ip_domain_cols(df, ctrs):
    try:
        df["ip"] = df["id"].apply(lambda x: get_ip_domain(x, ctrs)[0])
        df["domain"] = df["id"].apply(lambda x: get_ip_domain(x, ctrs)[1])
        df = df.astype({"ip": "string", "domain": "string"})
    except KeyError:
        pass
    return df


def get_ip_field(idx_ptrn):
    # if idx_ptrn == "nginx-access-*":
    #     return "nginx.access.remote_ip.keyword"
    # elif idx_ptrn == "telnet-*":
    #     return "telnet.ip.keyword"
    # elif idx_ptrn == "ftp-*":
    #     return "ftp.ip.keyword"
    # elif idx_ptrn == "postfix-smtpd-*":
    #     return "postfix_client_ip.keyword"
    return INDICES_IP_MAPPING[idx_ptrn]


def filter_placebo_ips(df):
    placebos = df[df["domain"].str.contains("placebo")]
    nonplacebos = df[~df["domain"].str.contains("placebo")]
    nonplacebo_ips = nonplacebos[~nonplacebos["client_ip"].isin(placebos["client_ip"])]
    nonplacebo_bot_ips = nonplacebos[nonplacebos["client_ip"].isin(placebos["client_ip"])]
    return placebos, nonplacebos, nonplacebo_ips, nonplacebo_bot_ips


def sum_idx_ptrns(df, col):
    tmp = df.groupby(["id"]).agg(col=(col, np.sum)).reset_index().rename(columns={"col": col})
    tmp["idx_ptrn"] = pd.Series(["*"] * tmp.shape[0])
    return tmp


def save_bot_ips(dfs, _file):
    tmp = pd.concat(dfs)
    bot_ips = sorted(list(tmp.client_ip.unique()))
    with open(_file, "w+") as f:
        for ip in bot_ips:
            f.write(f"{ip}\n")
    LOGGER.info(f"Saved {len(bot_ips)} bot IPs")


def get_other_bot_ips(idx_ptrn):
    bot_ips = set()
    for ptrn in BOT_IPS_MAPPING:
        if ptrn == idx_ptrn:
            continue
        with open(BOT_IPS_MAPPING[ptrn], "r") as f:
            idx_bot_ips = f.readlines()
            idx_bot_ips = [ip.rstrip() for ip in idx_bot_ips]
            bot_ips.update(idx_bot_ips)
    return bot_ips


# get placebo IPs
# placebos = sorted(list(utils.get_placebos().keys()))
# placebos = [str(_id) for _id in placebos]
# placebo_srvc_unique_ips = get_srvc_unique_ips(
#     PLACEBO_SRVC_UNIQUE_IPS_DF, ctids=placebos, filter_time=False
# )