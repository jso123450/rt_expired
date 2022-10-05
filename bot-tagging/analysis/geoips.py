# stdlib
from collections import defaultdict
import concurrent.futures as cfutures
from datetime import datetime
from pathlib import Path
import pdb

# 3p
from elasticsearch.exceptions import RequestError
from elasticsearch_dsl import A
import geoip2.database
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# import textdistance
from sklearn.metrics import jaccard_score

# proj
from enums import QueryEnum
import utils
import es_utils
import plot_utils as p_utils


###############################################################################


LOGGER = utils.get_logger("analysis")
TMP_DIR = Path("./analysis/geoips")
PLOTS_DIR = Path("./plots/geoips")
TMP_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in NONPLACEBOS]
SORTED_CTRS = utils.get_sorted_containers()
DEFAULT_TOP_N = 10

LOG_PROGRESS = {"nginx-access-*": 1_000, "telnet-*": 10_000, "ssh-*": 10_000, "ftp-*": 10_000}

UNKNOWN_ASN = -1
UNKNOWN_ASN_DESC = "Unknown"

ASN_DB = "/home/ubuntu/geolite2/GeoLite2-ASN_20210112/GeoLite2-ASN.mmdb"

###############################################################################


def _jaccard_score_wrapper(a, b):
    return jaccard_score(a, b, average="weighted")


def pairwise_jaccard(df):
    ctrs = list(sorted(df.ctr.unique()))
    rows = []
    scores = defaultdict(float)
    for ctr1 in ctrs:
        row = []
        asn1 = list(df[df.ctr == ctr1].org)
        for ctr2 in ctrs:
            _tuple1 = (ctr1, ctr2)
            _tuple2 = (ctr2, ctr1)
            key = _tuple2 if _tuple2 in scores else _tuple1
            if key in scores:
                score = scores[key]
            else:
                asn2 = list(df[df.ctr == ctr2].org)
                score = jaccard_score(asn1, asn2, average="weighted")
                # score = textdistance.jaccard(asn1, asn2)
                scores[key] = score
            row.append(score)
        rows.append(row)
    jaccard = pd.DataFrame(rows, columns=ctrs, index=ctrs)
    return jaccard


###############################################################################


def get_top_n_asn_ctrs(idx_ptrn, ctids, filename, n=DEFAULT_TOP_N):
    def _get_asn_from_ip(reader, ip):
        asn = None
        org = None
        try:
            res = reader.asn(ip)
            asn = res.autonomous_system_number
            org = res.autonomous_system_organization
        except ValueError:
            LOGGER.warning(f"  illegal IP {ip}")
        except (geoip2.errors.AddressNotFoundError):
            asn = UNKNOWN_ASN
            org = UNKNOWN_ASN_DESC
        return (asn, org)

    def _get_future(_exec, reader, ip):
        return _exec.submit(_get_asn_from_ip, reader, ip)

    LOGGER.info(f"get_top_n_asn_ctrs {idx_ptrn} {filename} {n} {ctids}")
    data = TMP_DIR / filename
    dtype = {"asn": "int32", "org": "string", "num_ips": "int32"}
    start_time = datetime.now()
    if data.exists():
        df = pd.read_csv(data)
    else:
        geoip_idx = es_utils.get_geoip_index(idx_ptrn)
        cols = ["asn", "org", "num_ips"]
        rows = []

        if ctids is not None:
            if len(ctids) == 1:
                cols.insert(0, "ctr")
                dtype["ctr"] = "category"

            asn_counts = defaultdict(int)
            asn_orgs = defaultdict(str)
            asn_orgs[UNKNOWN_ASN] = UNKNOWN_ASN_DESC
            search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids)
            ip_agg = {"ip": A("terms", field=es_utils.get_ip_field(idx_ptrn))}
            _generator = es_utils.scan_aggs(search, [ip_agg], size=1_000)
            batch_size = 1_000
            batched_ips = utils.batch_iterable(_generator, n=batch_size, key=lambda b: b.key.ip)
            with cfutures.ThreadPoolExecutor(max_workers=4) as executor:
                with geoip2.database.Reader(ASN_DB) as reader:
                    for idx, batch in enumerate(batched_ips):
                        if idx * batch_size % LOG_PROGRESS[idx_ptrn] == 0:
                            LOGGER.debug(f"  get_top_n_asn_ctrs on ip {idx*batch_size}...")
                        future_to_ip = {_get_future(executor, reader, ip): ip for ip in batch}
                        for future in cfutures.as_completed(future_to_ip):
                            ip = future_to_ip[future]
                            asn = None
                            org = None
                            try:
                                asn, org = future.result()
                            except Exception as e:
                                LOGGER.warning(f"err with future.result {ip}: {e}")
                            if asn is None or org is None:  # illegal IP
                                continue
                            asn_counts[asn] += 1
                            asn_orgs[asn] = org

            sorted_asn_counts = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)
            for asn, asn_count in sorted_asn_counts:
                org = asn_orgs[asn]
                row = [asn, org, asn_count]
                if len(ctids) == 1:
                    row.insert(0, ctids[0])
                rows.append(row)
        else:
            asn_agg = {"asn": A("terms", field="geoip.asn")}
            org_agg = {"org": A("terms", field="geoip.organization_name.keyword")}
            search = es_utils.init_query(
                QueryEnum.SEARCH, geoip_idx, filter_time=False, ctids=ctids
            )
            LOGGER.debug(f"get_top_n_asn_by_ctr search {search.to_dict()}")
            _generator = es_utils.scan_aggs(search, [asn_agg, org_agg], size=1_000)
            for idx, bucket in enumerate(_generator):
                if idx % LOG_PROGRESS[idx_ptrn] == 0:
                    LOGGER.debug(f"  get_top_n_asn_ctrs on bucket {idx}...")
                row = [bucket.key.asn, bucket.key.org, bucket.doc_count]
                rows.append(row)
        df = pd.DataFrame(rows, columns=cols)
        df.to_csv(data, index=False)
    df = df.astype(dtype)
    df = df.sort_values(by=["num_ips"], ascending=False)
    elapsed = datetime.now() - start_time
    LOGGER.info(f"Found {df.shape[0]} ASNs and {df.num_ips.sum()} IPs in {elapsed}.")
    if n is not None:
        df = df.head(n)
    return df


# def get_top_n_asn_ctrs(idx_ptrn, ctids, filename, n=DEFAULT_TOP_N):
#     LOGGER.info(f"get_top_n_asn_ctrs {idx_ptrn} {filename} {n} {ctids}")
#     data = TMP_DIR / filename
#     dtype = {"asn": "int32", "org": "string", "num_ips": "int32"}
#     if data.exists():
#         df = pd.read_csv(data)
#     else:
#         geoip_idx = es_utils.get_geoip_index(idx_ptrn)
#         cols = ["asn", "org", "num_ips"]
#         rows = []

#         if ctids is not None:
#             if len(ctids) == 1:
#                 cols.insert(0, "ctr")
#                 dtype["ctr"] = "category"

#             search_1 = es_utils.init_query(
#                 QueryEnum.SEARCH, geoip_idx, filter_time=False, ctids=None
#             )
#             asn_counts = defaultdict(int)
#             asn_orgs = defaultdict(str)
#             for idx, ip_hit in enumerate(search_1.scan()):
#                 if idx % LOG_PROGRESS[idx_ptrn] == 0:
#                     LOGGER.debug(f"  get_top_n_asn_ctrs on ip {idx}...")
#                 try:
#                     asn = ip_hit.geoip.asn
#                     org = ip_hit.geoip.organization_name
#                     asn_orgs[asn] = org
#                 except AttributeError:  # geoip lookup failed
#                     continue
#                 ip = ip_hit.ip
#                 search_2 = es_utils.init_query(
#                     QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids
#                 )
#                 search_2 = search_2.query("term", **{es_utils.get_ip_field(idx_ptrn): ip})
#                 response = search_2.execute()
#                 if response.hits.total.value > 0:
#                     asn_counts[asn] += 1
#                 # for _ in search_2.scan():
#                 #     asn_counts[asn] += 1
#                 #     break

#             # ctr_ips = es_utils.get_ips(idx_ptrn, ctids=ctids, filter_time=True, tag=None)
#             # for idx, bucket in enumerate(ctr_ips):
#             #     ip = bucket.key.ip
#             #     if idx % LOG_PROGRESS[idx_ptrn] == 0:
#             #         LOGGER.debug(f"  get_top_n_asn_ctrs on bucket {idx}...")
#             #     ip_search = es_utils.init_query(
#             #         QueryEnum.SEARCH, geoip_idx, filter_time=False, ctids=None
#             #     )
#             #     ip_search = ip_search.query("term", ip=ip)
#             #     for hit in ip_search.scan():
#             #         try:
#             #             asn = hit.geoip.asn
#             #             org = hit.geoip.organization_name
#             #             asn_counts[asn] += 1
#             #             asn_orgs[asn] = org
#             #         except AttributeError:  # geoip failed
#             #             pass
#             #         break
#             sorted_asn_counts = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)
#             for asn, asn_count in sorted_asn_counts:
#                 org = asn_orgs[asn]
#                 row = [asn, org, asn_count]
#                 if len(ctids) == 1:
#                     row.insert(0, ctids[0])
#                 rows.append(row)
#         else:
#             asn_agg = {"asn": A("terms", field="geoip.asn")}
#             org_agg = {"org": A("terms", field="geoip.organization_name.keyword")}
#             search = es_utils.init_query(
#                 QueryEnum.SEARCH, geoip_idx, filter_time=False, ctids=ctids
#             )
#             LOGGER.debug(f"get_top_n_asn_by_ctr search {search.to_dict()}")
#             _generator = es_utils.scan_aggs(search, [asn_agg, org_agg], size=1_000)
#             for idx, bucket in enumerate(_generator):
#                 if idx % LOG_PROGRESS[idx_ptrn] == 0:
#                     LOGGER.debug(f"  get_top_n_asn_ctrs on bucket {idx}...")
#                 row = [bucket.key.asn, bucket.key.org, bucket.doc_count]
#                 rows.append(row)
#         df = pd.DataFrame(rows, columns=cols)
#         df.to_csv(data, index=False)
#     df = df.astype(dtype)
#     df = df.sort_values(by=["num_ips"], ascending=False)
#     if n is not None:
#         df = df.head(n)
#     return df


def get_top_n_asn_placebos(idx_ptrn, n=DEFAULT_TOP_N):
    ctids = [str(_id) for _id in PLACEBOS]
    srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
    data = f"{srvc}-placebos-top_asn.csv"
    df = get_top_n_asn_ctrs(idx_ptrn, ctids, data, n=n)


def get_top_n_asn_nonplacebos(idx_ptrn, n=DEFAULT_TOP_N):
    def _get_top_n_asn_ctr(idx_ptrn, ctr, n):
        ctids = [str(ctr)]
        srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
        data = f"{srvc}-{ctr}-top_asn.csv"
        df = get_top_n_asn_ctrs(idx_ptrn, ctids, data, n=n)
        return df

    def _get_ctr_avgs(jaccard):
        avgs = {}
        for row in jaccard.itertuples():
            ctr = row.Index
            avg = np.mean(row[1:])
            avgs[ctr] = avg
        return avgs

    def _get_outliers(avgs, percentile=10):
        avg_values = list(avgs.values())
        percentiles = np.percentile(
            avg_values, [percentile, 100 - percentile], interpolation="midpoint"
        )
        outliers = {}
        outliers.update({ctr: avgs[ctr] for ctr in avgs if avgs[ctr] <= percentiles[0]})
        outliers.update({ctr: avgs[ctr] for ctr in avgs if avgs[ctr] >= percentiles[-1]})
        return outliers, percentiles

    def _get_ctrs_below_sum(jaccard, thresh=2.0):
        below = {}
        for row in jaccard.itertuples():
            ctr = row.Index
            rest = np.sum(row[1:])
            if rest <= thresh:
                below[ctr] = rest
        return below

    srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
    data = TMP_DIR / f"{srvc}-nonplacebos-top_asn.csv"
    ctids = list(SORTED_CTRS)
    ctids = [ctid for ctid in ctids if int(ctid) in NONPLACEBOS]
    if not data.exists():
        dfs = {ctid: _get_top_n_asn_ctr(idx_ptrn, ctid, n=n) for ctid in ctids}
        df = dfs[ctids[0]]
        for ctid in ctids[1:]:
            ctid_df = dfs[ctid]
            df = df.append(ctid_df)
        del dfs
        df.to_csv(data, index=False)
    else:
        df = pd.read_csv(data)
    dtype = {"ctr": "category", "asn": "int32", "org": "string", "num_ips": "int32"}
    df = df.astype(dtype)
    df = df.sort_values(by=["num_ips"], ascending=False)

    jaccard_file = TMP_DIR / "jaccard-nonplacebos-top_asn.csv"
    if jaccard_file.exists():
        jaccard = pd.read_csv(jaccard_file, header=0)
        jaccard = jaccard.rename(columns={"Unnamed: 0": "ctr"})
        jaccard = jaccard.set_index("ctr")
    else:
        jaccard = pairwise_jaccard(df)
        jaccard.to_csv(jaccard_file, index=True, header=True)
        ax = sns.heatmap(jaccard, cmap=sns.cm.rocket_r)
        ax.set_title("Jaccard Score Heatmap")
        plt.savefig(PLOTS_DIR / "heatmap-jaccard-asn.png")
        plt.clf()

    ctr_jaccard_avgs = _get_ctr_avgs(jaccard)
    # boxplot of ctr jaccard avgs
    sns.set_theme(style="whitegrid")
    ax = sns.boxplot(x=pd.Series(ctr_jaccard_avgs.values()))
    ax.set_title("Average Pairwise Jaccard Score by Domain")
    plt.savefig(PLOTS_DIR / "boxplot-jaccard-avg.png")
    plt.clf()

    percentiles = range(1, 11)
    for percentile in percentiles:
        outliers, bounds = _get_outliers(ctr_jaccard_avgs, percentile=percentile)
        LOGGER.info(
            f"percentile={percentile} outliers {list(outliers.keys())} ({len(outliers)})  bounds={bounds} avgs={outliers}"
        )


def get_asn_distribution(idx_ptrn):
    srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
    data = f"{srvc}-asn_dist.csv"
    df = get_top_n_asn_ctrs(idx_ptrn, None, data, n=None)

    plot_file = PLOTS_DIR / f"{srvc}-hist-asn.png"
    LOGGER.debug(f"get_asn_distribution {idx_ptrn} plotting {plot_file}...")
    num_ips = df.num_ips
    num_ips = np.log(num_ips)
    _, ax = plt.subplots(nrows=1, ncols=1)
    ax.hist(num_ips, bins="auto")
    ax.set_yscale("log")
    ax.set_xlabel("Log Number of IPs Seen / ASN")
    ax.set_ylabel("Log Count")
    ax.set_title("Number of IPs Seen per ASN")
    p_utils.style_grid(ax)
    plt.savefig(plot_file, facecolor="white")
    plt.clf()

    plot_file = PLOTS_DIR / f"{srvc}-bar-asn.png"
    LOGGER.debug(f"get_asn_distribution {idx_ptrn} plotting {plot_file}...")
    tmp = df.head(20)
    labels = [f"{org[:10]}.." for org in tmp.org]
    _, ax = plt.subplots(nrows=1, ncols=1)
    ax.bar(labels, tmp.num_ips)
    ax.set_yscale("log")
    ax.set_xlabel("Organization")
    ax.set_ylabel("Log Count")
    ax.set_title("Top ASNs by Number of IPs Seen")
    ax.set_xticklabels(labels, rotation=90, ha="right")
    p_utils.style_grid(ax)
    plt.tight_layout()
    plt.savefig(plot_file, facecolor="white")
    plt.clf()

    LOGGER.debug(f"get_asn_distribution {idx_ptrn} done...")


###############################################################################

# FUNCS = [get_asn_distribution, get_top_n_asn_placebos, get_top_n_asn_nonplacebos]
FUNCS = [get_top_n_asn_nonplacebos]


def analyze(idx_ptrn):
    for func in FUNCS:
        func(idx_ptrn)