from collections import defaultdict
import json
from pathlib import Path
import re

from elasticsearch_dsl import Search, A
import pandas as pd

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
}
ALL_SRVC_UNIQUE_IPS_DF = Path(CONFIG["ARTIFACT_DIR"]) / "all_srvc_unique_ips.csv"
FILTERED_SRVC_UNIQUE_IPS_DF = Path(CONFIG["ARTIFACT_DIR"]) / "filtered_srvc_unique_ips.csv"


# def init_ctr_logs(path):
#     ctr_logs = defaultdict(lambda: defaultdict(int))
#     try:
#         with open(path, "r") as f:
#             loaded = json.loads(f.read())
#         for ctr in loaded:  # keep it the defaultdict(...)
#             for idx_ptrn in loaded[ctr]:
#                 ctr_logs[ctr][idx_ptrn] = loaded[ctr][idx_ptrn]
#     except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
#         pass
#     return ctr_logs


# def write_ctr_logs(ctr_logs, path):
#     with open(path, "w+") as f:
#         json.dump(ctr_logs, f)


def get_field(hit, traversal):
    field = hit
    for key in traversal:
        if field == None:
            break
        field = field.get(key, None)
    return field if field != hit else None


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


def scan_idx_aggs(
    csv,
    source_aggs_map,
    indices,
    process_bucket,  # appends to a file
    cols,
    filter_time=False,
    windows=CONFIG["TIME"]["WINDOWS"],
    time_fmt=TIME_FMT,
):
    _file = open(csv, "w+")
    cols_str = SEP.join(cols)
    _file.write(f"{cols_str}\n")
    try:
        for idx, idx_ptrn in enumerate(indices):
            LOGGER.info(f"Processing {idx_ptrn}...{len(indices)-idx-1} left")
            s = Search(index=idx_ptrn)
            if filter_time:
                idx_windows = windows.get(idx_ptrn, windows["DEFAULT"])
                start_window = idx_windows["START"]
                end_window = idx_windows["END"]
                s = s.filter(
                    "range",
                    **{"@timestamp": {"gte": start_window, "lt": end_window, "format": time_fmt}},
                )
            # s = s.params(scroll="10m")
            print(s.to_dict())
            # pdb.set_trace()
            for idx, bucket in enumerate(scan_aggs(s, source_aggs_map[idx_ptrn], size=1_000)):
                if idx % 100_000 == 0:
                    LOGGER.info(f"  at bucket {idx}...")
                row = process_bucket(bucket)
                if row is not None:
                    _file.write(row)
    finally:
        _file.close()
    return pd.read_csv(csv, header=0, sep=re.escape(SEP))


def query_scan_idx_aggs(csv, source_aggs_map, indices, process_bucket, cols, filter_time):
    df = None
    try:
        df = pd.read_csv(csv, header=0, sep=re.escape(SEP))
        LOGGER.info(f"Loaded from {csv}.")
    except FileNotFoundError:
        df = scan_idx_aggs(
            csv,
            source_aggs_map,
            indices,
            process_bucket,
            cols,
            filter_time=filter_time,
            windows=CONFIG["TIME"]["WINDOWS"],
            time_fmt=TIME_FMT,
        )
    return df


def scan_idx(idx_ptrn, process_hit, bot_ips, windows=CONFIG["TIME"]["WINDOWS"], time_fmt=TIME_FMT):
    bot_rows = []
    client_rows = []
    LOGGER.info(f"Processing {idx_ptrn}...")
    idx_windows = windows.get(idx_ptrn, windows["DEFAULT"])
    start_window = idx_windows["START"]
    end_window = idx_windows["END"]
    s = Search(index=idx_ptrn)
    s = s.filter(
        "range", **{"@timestamp": {"gte": start_window, "lt": end_window, "format": time_fmt}}
    )
    s = s.params(size=1_000)
    for idx, hit in enumerate(s.scan()):
        if idx % 1_000 == 0:
            LOGGER.info(f" at doc {idx}...")
        bot, row = process_hit(hit, bot_ips)
        if row is None:
            continue
        if bot:
            bot_rows.append(row)
        else:
            client_rows.append(row)
    return bot_rows, client_rows


def get_ip_domain(ctid, ctrs):
    try:
        ip = ctrs[int(ctid)]["ip"]
        domain = ctrs[int(ctid)]["domain"]
        return ip, domain
    except KeyError:  # test container
        return None, None


def add_ip_domain_cols(df, ctrs):
    df["ip"] = df["id"].apply(lambda x: get_ip_domain(x, ctrs)[0])
    df["domain"] = df["id"].apply(lambda x: get_ip_domain(x, ctrs)[1])
    df = df.astype({"ip": "string", "domain": "string"})
    return df


def get_ip_field(idx_ptrn):
    if idx_ptrn == "nginx-access-*":
        return "nginx.access.remote_ip.keyword"
    elif idx_ptrn == "telnet-*":
        return "telnet.ip.keyword"
    elif idx_ptrn == "ftp-*":
        return "ftp.ip.keyword"
    elif idx_ptrn == "postfix-smtpd-*":
        return "postfix_client_ip.keyword"


def get_srvc_unique_ips(csv, filter_time=False):
    def _process_bucket(idx_ptrn, bucket):
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        ip, domain = get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:
            return None
        row = [ctid, domain, ip, idx_ptrn, client_ip, str(bucket.doc_count)]
        output = f"{SEP.join(row)}\n"
        return output

    source_aggs = [{"ctid": A("terms", field="container.id.keyword")}]
    source_aggs_map = {}
    for idx_ptrn in INDICES_IP_MAPPING:
        ip_agg = {"ip": A("terms", field=get_ip_field(idx_ptrn))}
        idx_aggs = list(source_aggs)
        idx_aggs.append(ip_agg)
        source_aggs_map[idx_ptrn] = idx_aggs
    cols = ["id", "domain", "ip", "idx_ptrn", "client_ip", "count"]
    df = query_scan_idx_aggs(
        csv, source_aggs_map, INDICES_IP_MAPPING, _process_bucket, cols, filter_time
    )
    df = df.astype(
        {
            "id": "string",
            "domain": "string",
            "ip": "string",
            "idx_ptrn": "string",
            "client_ip": "string",
        }
    )
    return df


def filter_placebo_ips(df):
    placebos = df[df["domain"].str.contains("placebo")]
    nonplacebos = df[~df["domain"].str.contains("placebo")]
    nonplacebo_ips = nonplacebos[~nonplacebos["client_ip"].isin(placebos["client_ip"])]
    nonplacebo_bot_ips = nonplacebos[nonplacebos["client_ip"].isin(placebos["client_ip"])]
    return placebos, nonplacebos, nonplacebo_ips, nonplacebo_bot_ips
