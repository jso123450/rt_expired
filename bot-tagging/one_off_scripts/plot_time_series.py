from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import sys
import pdb

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))

DATA_DIR = MAIN_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOT_DIR = MAIN_DIR / "plots" / "time_series"
PLOT_DIR.mkdir(exist_ok=True)


from elasticsearch_dsl import A, Q, Search
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter, MonthLocator
import numpy as np

from enums import QueryEnum, TagEnum
import utils
import es_utils

LOGGER = utils.get_logger("one_off")

# IDX_PTRNS = ["nginx-access-*"]
# IDX_PTRNS = ["nginx-access-*", "ssh-*", "telnet-*", "ftp-*"]
IDX_PTRN_SRVCS = {
    "nginx-access-*": "80, 443 (HTTP(S))",
    "ssh-*": "22 (SSH)",
    "telnet-*": "23 (Telnet)",
    "ftp-*": "21 (FTP)",
}
CONFIG = utils.get_config()
CFG_TIME_FMT_PY = "%Y-%m-%d"
CFG_TIME_FMT_ES = CONFIG["TIME"]["FMT"]
CFG_TIME_START = CONFIG["TIME"]["WINDOWS"]["START"]
CFG_TIME_END = CONFIG["TIME"]["WINDOWS"]["END"]
DH_KEY_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
CAL_INTERVAL = "1d"
NONPLACEBOS = utils.get_nonplacebos()

DATA_FILE = DATA_DIR / "time-series_services.csv"
DATA_FILE_BUCKET = DATA_DIR / "bucketed.csv"

FILTER_START = np.datetime64("2019-08-01")
FILTER_END = np.datetime64("2019-11-29")

RAW_PORT_DATA = Path("/mnt/analysis_artifacts/port_analysis/results.json")

###############################################################################


def get_num_days(start_time, end_time, fmt):
    start = datetime.strptime(start_time, fmt)
    end = datetime.strptime(end_time, fmt)
    return (end - start).days


def get_num_days_ctid(df, ctid):
    tmp = df[df.ctid == ctid]
    return tmp.shape[0]


def get_num_days_df(df):
    rows = []
    cols = ["idx_ptrn", "ctid", "num_days"]
    for idx_ptrn in IDX_PTRN_SRVCS:
        for ctid in NONPLACEBOS:
            tmp = df[["ctid", "date", idx_ptrn]]
            tmp = tmp[(tmp.ctid == ctid) & (tmp[idx_ptrn] > 0)]
            rows.append([idx_ptrn, ctid, tmp.shape[0]])
    num_days_df = pd.DataFrame(rows, columns=cols)
    dtype = {"idx_ptrn": "category", "ctid": "int16", "num_days": "int16"}
    return num_days_df.astype(dtype)


def get_df(data):
    cols = ["ctid", "date", *IDX_PTRN_SRVCS, "total"]
    # cols = ["idx_ptrn", "ctid", "date", "num_reqs"]
    dtype = {"ctid": "category", "date": "datetime64[ns]"}
    _dict = defaultdict(lambda: defaultdict(dict))
    if data.exists():
        df = pd.read_csv(data)
    else:
        for idx_ptrn in IDX_PTRN_SRVCS:
            LOGGER.info(f"get_df idx_ptrn {idx_ptrn}")
            for idx, ctid in enumerate(NONPLACEBOS):
                if idx % 50 == 0:
                    LOGGER.debug(f"  on idx {idx} ctid={ctid}")
                search = (
                    Search(index=idx_ptrn)
                    .params(size=0)
                    .filter(
                        "range",
                        **{
                            "@timestamp": {
                                "gte": CFG_TIME_START,
                                "lt": CFG_TIME_END,
                                "format": CFG_TIME_FMT_ES,
                            }
                        },
                    )
                )
                ctid_filter = Q("term", log__container__keyword=ctid)
                search = search.filter(ctid_filter)
                agg = A("date_histogram", field="@timestamp", calendar_interval=CAL_INTERVAL)
                search.aggs.bucket("reqs_over_time", agg)
                res = search.execute()
                for bucket in res.aggs.reqs_over_time.buckets:
                    str_date = bucket.key_as_string
                    date = datetime.strptime(str_date, DH_KEY_FMT)
                    start_window = datetime.strptime(CFG_TIME_START, CFG_TIME_FMT_PY)
                    end_window = datetime.strptime(CFG_TIME_END, CFG_TIME_FMT_PY)
                    if date < start_window or date >= end_window:
                        continue
                    _dict[ctid][date][idx_ptrn] = bucket.doc_count
        rows = []
        for ctid in _dict:
            for date in _dict[ctid]:
                row = [ctid, date]
                srvc_reqs = []
                for idx_ptrn in IDX_PTRN_SRVCS:
                    reqs = _dict[ctid][date].get(idx_ptrn, 0)
                    srvc_reqs.append(reqs)
                row.extend(srvc_reqs)
                row.append(sum(srvc_reqs))
                rows.append(row)
        df = pd.DataFrame(rows, columns=cols)
        df.to_csv(data, index=False)
    df = df.astype(dtype)
    return df


def get_raw_port_df():
    def _get_all_ports(data):
        all_ports = set()
        for ctid in data:
            for date in data[ctid]:
                all_ports.update(data[ctid][date]["dport"].keys())
        all_ports = [int(port) for port in all_ports]
        return sorted(all_ports)

    with open(RAW_PORT_DATA, "r") as f:
        raw_data = json.load(f)
    all_dports = _get_all_ports(raw_data)
    prefixed_dports = [f"port_{port}" for port in all_dports]
    cols = ["ctid", "date", *all_dports, "total"]
    rows = []
    for ctid in raw_data:
        for date in raw_data[ctid]:
            row = [int(ctid), date]
            port_reqs = []
            for port in all_dports:
                reqs = raw_data[ctid][date]["dport"].get(port, 0)
                port_reqs.append(reqs)
            row.extend(port_reqs)
            row.append(sum(port_reqs))
    dtype = {"ctid": "category", "date": "datetime64[ns]"}
    df = pd.DataFrame(rows, columns=cols)
    df = df.astype(dtype)
    return df


def join_data(srvc_data, port_data):
    df = srvc_data.join(
        port_data, on=["ctid", "date"], how="outer", lsuffix="_srvc", rsuffix="_port"
    )
    df["total"] = df["total_srvc"] + df["total_port"]
    df = df.drop(columns=["total_srvc", "total_port"])
    return df


###############################################################################


def plot_num_days_hist(df, max_days):
    num_days_df = get_num_days_df(df)
    for idx_ptrn in IDX_PTRN_SRVCS:
        tmp = num_days_df[num_days_df.idx_ptrn == idx_ptrn]
        fig, ax = plt.subplots(nrows=1, ncols=1)
        ax.hist(tmp.num_days, bins="auto")
        ax.set_ylabel("Number of Domains")
        ax.set_xlabel(f"Number of Days with Requests in Time Window (max={max_days})")
        plt.title("Number of Days with Requests for Each Domain")
        plt.savefig(PLOT_DIR / f"hist-num_days-{idx_ptrn}.png", facecolor="white")
        plt.clf()
    return num_days_df


# def transform(df):
#     cols = ["ctid", "date", *IDX_PTRN_SRVCS, "total"]
#     rows = []
#     LOGGER.info(f"transform")
#     for ctid in NONPLACEBOS:
#         tmp1 = df[df.ctid == ctid]
#         for date in tmp1.date:
#             tmp2 = tmp1[tmp1.date == date]
#             day_reqs = []
#             for idx_ptrn in IDX_PTRN_SRVCS:
#                 reqs = 0
#                 try:
#                     reqs = tmp2[tmp2.idx_ptrn == idx_ptrn].iloc[0].num_reqs
#                 except IndexError:
#                     pass
#                 day_reqs.append(reqs)
#             row = [ctid, date, *day_reqs, sum(day_reqs)]
#             rows.append(row)
#     new_df = pd.DataFrame(rows, columns=cols)
#     new_df = new_df.astype({"ctid": "category", "date": "datetime64[ns]"})
#     LOGGER.info(f"transform finished")
#     return new_df


# def plot_time_service(df):
#     bounds = [
#         "2019-08-01",
#         "2019-08-15",
#         "2019-09-01",
#         "2019-09-15",
#         "2019-10-01",
#         "2019-10-15",
#         "2019-11-01",
#         "2019-11-15",
#         "2019-12-01",
#     ]
#     bounds = [datetime.strptime(b, "%Y-%m-%d") for b in bounds]
#     tmp = df
#     series = []
#     for idx_ptrn in IDX_PTRN_SRVCS:
#         tmp2 = tmp[["ctid", "date", idx_ptrn]]
#         counts = []
#         for i in range(len(bounds)):
#             if i == len(bounds) - 1:
#                 continue
#             b1 = bounds[i]
#             b2 = bounds[i + 1]
#             tmp3 = tmp2[(b1 <= tmp2.date) & (tmp2.date < b2)]
#             interval_count = tmp3[idx_ptrn].sum()
#             counts.append(interval_count)
#         series.append((idx_ptrn, counts))

#     _, ax = plt.subplots(1, 1)
#     for (name, pts) in series:
#         ax.plot(bounds[:-1], pts, label=name)
#     ax.set_yscale("log")
#     ax.grid(True)
#     ax.set_xlabel("Month")
#     ax.set_ylabel("Total Incoming Requests to Monitored Services")
#     ax.set_title("Incoming Requests for Each Monitored Services")
#     ax.legend(loc="upper left")

#     ax.xaxis.set_major_locator(MonthLocator())
#     ax.xaxis.set_major_formatter(DateFormatter("%m-%Y"))
#     plt.savefig(PLOT_DIR / "time-service.png", facecolor="white")
#     plt.clf()


def plot_time_service(df):
    def _get_data(tmp_df, idx_ptrn, func="mean"):
        bkt_data = []
        cols = ["date", "total"]
        dates = sorted(tmp_df.date.unique())
        dates = [date for date in dates if FILTER_START <= date and date < FILTER_END]
        for date in dates:
            tmp = tmp_df[tmp_df.date == date]
            metric = tmp[idx_ptrn].sum()
            if func == "mean":
                metric = tmp[idx_ptrn].mean()
            bkt_data.append([date, metric])
        bkt_data = pd.DataFrame(bkt_data, columns=cols)
        bkt_data = bkt_data.astype(
            {
                "date": "datetime64[ns]",
                "total": "int64",
            }
        )
        return bkt_data

    labels = []
    data = []
    for idx_ptrn, srvc in IDX_PTRN_SRVCS.items():
        tmp = df[["ctid", "date", idx_ptrn]]
        bkt_data = _get_data(tmp, idx_ptrn)
        data.append(bkt_data)
        labels.append(srvc)

    tmp = df[["ctid", "date", "total"]]
    bkt_data = _get_data(tmp, "total")
    data.insert(0, bkt_data)
    labels.insert(0, "Total")

    _, ax = plt.subplots(1, 1)
    fmts = ["--", "p-", "v-", "s-", "o-"]
    for idx, bkt_data in enumerate(data):
        ax.plot(bkt_data.date, bkt_data.total, fmts[idx], label=labels[idx], markevery=10)
    ax.set_yscale("log")
    ax.grid(True)
    # ax.set_xlabel("Date") # unnecessary
    ax.set_ylabel("Number of Requests")
    # ax.set_title("Average Traffic to Monitored Services")
    # ax.legend(loc="best")
    ax.legend(loc="center left", bbox_to_anchor=(1, 0.5))

    ax.xaxis.set_major_locator(MonthLocator())
    ax.xaxis.set_major_formatter(DateFormatter("%b %Y"))
    plt.tight_layout()
    plt.savefig(PLOT_DIR / "time-service.png", facecolor="white")
    plt.clf()


def plot_time_traffic_buckets(df):
    def _get_data(tmp_df, func="mean"):
        bkt_data = []
        cols = ["date", "total"]
        dates = sorted(tmp_df.date.unique())
        dates = [date for date in dates if FILTER_START <= date and date < FILTER_END]
        for date in dates:
            tmp = tmp_df[tmp_df.date == date]
            metric = tmp.total.sum()
            if func == "mean":
                metric = tmp.total.mean()
            bkt_data.append([date, metric])
        bkt_data = pd.DataFrame(bkt_data, columns=cols)
        bkt_data = bkt_data.astype(
            {
                "date": "datetime64[ns]",
                "total": "int64",
            }
        )
        return bkt_data

    bucket_df = pd.read_csv(DATA_FILE_BUCKET)
    max_ctr = 657
    tmp = df[df.ctid != max_ctr]
    buckets = sorted(bucket_df.bucket.unique(), reverse=True)
    data = []
    labels = [
        "Max ($100$th percentile)",
        "High ($<100$th percentile)",
        "Overall (excluding max)",
        "Medium ($<90$th percentile)",
        "Low ($<50$th percentile)",
    ]
    for bucket in buckets:
        tmp_buckets = bucket_df[bucket_df.bucket == bucket]
        tmp2 = tmp[tmp.ctid.isin(tmp_buckets.ctid)]
        bkt_data = _get_data(tmp2)
        data.append(bkt_data)

    tmp = df[df.ctid == max_ctr]
    bkt_data = _get_data(tmp)
    data.insert(0, bkt_data)

    tmp = df[df.ctid != max_ctr]
    bkt_data = _get_data(tmp, func="mean")
    data.insert(2, bkt_data)

    _, ax = plt.subplots(1, 1)
    fmts = ["p-", "s-", "--", "v-", "o-"]
    for idx, bkt_data in enumerate(data):
        ax.plot(bkt_data.date, bkt_data.total, fmts[idx], label=labels[idx], markevery=10)
    ax.set_yscale("log")
    ax.grid(True)
    ax.set_xlabel("Date")
    ax.set_ylabel("Number of Incoming Requests on Monitored Services")
    # ax.set_title("Bucketed Average Traffic Volume Levels")
    ax.legend(loc="best")

    ax.xaxis.set_major_locator(MonthLocator())
    ax.xaxis.set_major_formatter(DateFormatter("%b %Y"))
    plt.savefig(PLOT_DIR / "time-traffic_bkts.png", facecolor="white")
    plt.clf()

    return labels, fmts, data


###############################################################################


def _get_trust_ips_time(idx_ptrn, ctid, ips):
    search = (
        Search(index=idx_ptrn)
        .params(size=0)
        .filter(
            "range",
            **{
                "@timestamp": {
                    "gte": CFG_TIME_START,
                    "lt": CFG_TIME_END,
                    "format": CFG_TIME_FMT_ES,
                }
            },
        )
    )
    query = Q(
        "bool",
        filter=[Q("term", log__container__keyword=ctid)],
        should=[Q("term", **{es_utils.get_ip_field(idx_ptrn): ip}) for ip in ips],
        minimum_should_match=1,
    )
    search = search.query(query)
    agg = A("date_histogram", field="@timestamp", calendar_interval=CAL_INTERVAL)
    search.aggs.bucket("reqs_over_time", agg)
    res = search.execute()
    data = {}
    for bucket in res.aggs.reqs_over_time.buckets:
        str_date = bucket.key_as_string
        date = datetime.strptime(str_date, DH_KEY_FMT)
        start_window = datetime.strptime(CFG_TIME_START, CFG_TIME_FMT_PY)
        end_window = datetime.strptime(CFG_TIME_END, CFG_TIME_FMT_PY)
        if date < start_window or date >= end_window:
            continue
        data[date] = bucket.doc_count
    return data


# def plot_time_trust(data, n=5):
#     def _get_top_trust_ctids():
#         from analysis import ctr_status

#         filepath = "../results/ctr_status.jsonl"
#         df = ctr_status.get_tag_ctr_status_df(filepath)
#         df = ctr_status.aggregate_blocklist_cols(filepath)

#         user_col_name = "user_percent"
#         funcs = {
#             user_col_name: lambda x: (x.user) / (x.bot + x.both + x.user + x.untagged),
#         }
#         for col_name, _func in funcs.items():
#             df[col_name] = df.apply(_func, axis=1)
#         df = df.sort_values(by=[user_col_name], ascending=False)
#         ctids = df.head(n).ctid.tolist()
#         return ctids

#     def _update_batched_data(data, ctid, partial):
#         if ctid not in data:
#             data[ctid] = partial
#             return
#         for date, num in partial.items():
#             base = data[ctid].get(date, 0)
#             data[ctid][date] = base + num

#     if not data.exists():
#         idx_ptrn = "nginx-access-*"
#         cols = ["ctid", "date", idx_ptrn]
#         ip_idx = es_utils.get_geoip_index(idx_ptrn)
#         search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
#         query = Q(
#             "bool",
#             filter=[Q("exists", field=es_utils.USER_TAGS_FIELD)],
#             must_not=[Q("exists", field=es_utils.BOT_TAGS_FIELD)],
#         )
#         search = search.query(query)
#         ips = es_utils.get_ips(idx_ptrn, search=search, with_agg=False)
#         ips = set(ip for ip in ips)
#         batch_size = 500
#         batches = utils.batch_iterable(ips, n=batch_size)
#         data = {}
#         ctids = _get_top_trust_ctids()
#         for idx, batch in enumerate(batches):
#             if idx % 200 == 0:
#                 LOGGER.debug(f"  on batch {idx} ip {idx*batch_size}...")
#             for ctid in ctids:
#                 batch_data = _get_trust_ips_time(idx_ptrn, ctid, batch)
#                 _update_batched_data(data, ctid, batch_data)
#         rows = []
#         for ctid in data:
#             for date, num in data[ctid].items():
#                 row = [ctid, date, num]
#                 rows.append(row)
#         df = pd.DataFrame(rows, columns=cols)
#         df.to_csv(data, index=False)
#     else:
#         df = pd.read_csv(data)


###############################################################################


def main():
    df = get_df(DATA_FILE)
    # LOGGER.debug(f"df loaded")
    max_days = get_num_days(CFG_TIME_START, CFG_TIME_END, CFG_TIME_FMT_PY)
    num_days_df = plot_num_days_hist(df, max_days)
    # LOGGER.debug(f"max_days={max_days}")
    # df = transform(df)
    # pdb.set_trace()
    plot_time_service(df)
    plot_time_traffic_buckets(df)
    # for ctid in NONPLACEBOS:
    #     num_days_ctid = get_num_days_ctid(df, ctid)
    #     if num_days_ctid != num_days:
    #         print(f"  ctid={ctid} num_days_ctid={num_days_ctid}")


if __name__ == "__main__":
    main()