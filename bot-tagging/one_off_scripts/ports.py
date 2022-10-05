import bz2
from collections import defaultdict, Counter
import concurrent.futures as cfutures
from contextlib import contextmanager
from datetime import datetime
import glob
import json
from pathlib import Path
import re
from string import Template
import subprocess
import sys
import pdb
import traceback

import dpkt

from dateutil import parser

from elasticsearch_dsl import A, Q, Search
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter, MonthLocator
import numpy as np
import seaborn as sns
from seaborn.rcmod import _AxesStyle
from sklearn.metrics import jaccard_score
from geoip2.errors import AddressNotFoundError

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))

from enums import QueryEnum, TagEnum
import utils
import es_utils


###############################################################################

CONFIG = utils.get_config()
LOGGER = utils.get_logger("one_off")
CTRS = utils.get_containers()
NONPLACEBOS = utils.get_nonplacebos()
PLACEBOS = utils.get_placebos()

TCPDUMP_DIR = Path("/mnt/tcpdump")

DATA_DIR = Path("/mnt/analysis_artifacts/port_analysis")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HDRS_DATA_DIR = Path("/mnt/analysis_artifacts/headers-port_analysis")  # from prior run

PLOT_DIR = MAIN_DIR / "plots" / "ports"
PLOT_DIR.mkdir(exist_ok=True)

RES_DATA_DIR = DATA_DIR / "results"
RES_DATA_DIR.mkdir(exist_ok=True)
RES_HDRS_DIR = HDRS_DATA_DIR / "results"  # from prior run
RES_NONHTTP_DIR = DATA_DIR / "nonhttp"
RES_NONHTTP_DIR.mkdir(exist_ok=True)

FILE_GLOBS = [
    TCPDUMP_DIR / "dump-18*.data.pcap*.bz2",  # dump-18_10_13_00_13_23.data.pcap.1036.bz2
    TCPDUMP_DIR / "dump-18*.data.pcap.9*.bz2",
    TCPDUMP_DIR / "dump-19*.data.pcap*bz2",
]
DUMP18_DATA_FIRST_IN_RANGE = 1036
DUMP18_HEADERS_FIRST_IN_RANGE = 82068

PROCESSED_FILES_FILE = DATA_DIR / "processed-files.txt"
PROCESSED_NONHTTP_FILE = DATA_DIR / "processed-nonhttp-files.txt"
# RESULTS_FILE = DATA_DIR / "results.json"
BUCKETS_FILE = MAIN_DIR / "data" / "ports-bucketed.csv"
TIME_TRUST_FILE = MAIN_DIR / "data" / "time-ports-trusted.csv"

TIME_FMT = "%Y-%m-%d"
WINDOW_START = datetime.strptime(CONFIG["TIME"]["WINDOWS"]["START"], TIME_FMT)
WINDOW_END = datetime.strptime(CONFIG["TIME"]["WINDOWS"]["END"], TIME_FMT)
FILTER_END = datetime.strptime("2019-11-26", TIME_FMT)

NUM_WORKERS = 4
DEFAULT_TOP_N = 5
BATCH_SIZE = 15 * NUM_WORKERS

CMD_BZIP2 = Template("bzip2 -cd $file")
CMD_TCPDUMP = "tcpdump -tttt -n -r - 'dst net 130.245.0.0/16'"
CMD_AWK = "awk '{{print $1,$2,$4,$6}}'"
CMD_SED = "sed 's|:$||'"  # remove trailing ':' if present
NONHONEY_CTID_PORTS = {
    "845": ["8000", "6600"],
    "675": ["53"],
    "679": ["53"],
    "667": ["53"],
    "664": ["25"],
    "678": ["53"],
    "687": ["53"],
    "730": ["53"],
}


###############################################################################


def get_files():
    for file_glob in FILE_GLOBS:
        globber = glob.iglob(str(file_glob))
        for file in globber:
            _yield = "dump-18" not in file
            if not _yield:
                fname = Path(file).name
                num = int(fname.split(".")[-2])
                _yield = num >= DUMP18_DATA_FIRST_IN_RANGE
            if _yield:
                yield file


@contextmanager
def get_pcap_rdr(file):
    f = bz2.open(file, "r")
    try:
        yield dpkt.pcap.Reader(f)
        # yield PcapReader(f)
    finally:
        f.close()


###############################################################################
# ORIGINAL RES


def load_processed_files(_file=PROCESSED_FILES_FILE):
    return set(utils._get_lines(_file))


def write_processed_files(files, _file=PROCESSED_FILES_FILE):
    # LOGGER.debug(f" write_processed_files {_file} {len(files)}")
    with open(_file, "w+") as f:
        out = "\n".join(files)
        f.write(out)


def load_results(_file):
    try:
        with open(_file, "r") as f:
            loaded = json.load(f)
    except FileNotFoundError:
        loaded = {}
    return loaded


def update_ctid_results(r1, r2):
    int_values = ["dport", "transport"]
    if len(r1) == 0:
        r1.update(r2)
        return
    for date, r2_date in r2.items():
        if date not in r1:
            r1[date] = r2_date
            continue
        for _key in int_values:
            for val, num in r2_date[_key].items():
                base = r1[date][_key].get(val, 0)
                r1[date][_key][val] = base + num
        r1_senders = set(r1[date]["senders"])
        r2_senders = set(r2[date]["senders"])
        r1[date]["tcp_syn"] += r2_date["tcp_syn"]
        union_senders = r1_senders.union(r2_senders)
        r1[date]["senders"] = list(union_senders)


def update_results(r1, r2, update_ctid_func=update_ctid_results):
    for ctid, r2_ctid in r2.items():
        if ctid not in r1:
            r1[ctid] = r2_ctid
            continue
        update_ctid_func(r1[ctid], r2[ctid])


def load_split_results(ctids=[], types=["data"], update_ctid_func=update_ctid_results):
    data_dirs = []
    for _type in types:
        if _type == "data":
            data_dirs.append(RES_DATA_DIR)
        if _type == "headers":
            data_dirs.append(RES_HDRS_DIR)
        if _type == "non-http":
            data_dirs.append(RES_NONHTTP_DIR)
    results = defaultdict(dict)
    for data_dir in data_dirs:
        _files = data_dir.glob("*.json")
        for _file in _files:
            ctid = _file.name[: _file.name.index(".json")]
            if ctid in ctids:
                update_ctid_func(results[ctid], load_results(_file))
    return results


def write_result(_file, results):
    with open(_file, "w+") as f:
        json.dump(results, f, indent=2)


def write_split_result(results, dir, batch, update_ctid_func=update_ctid_results):
    start_time = datetime.now()
    for ctid, ctid_info in results.items():
        ctid_file = dir / f"{ctid}.json"
        loaded = load_results(ctid_file)
        update_ctid_func(loaded, ctid_info)
        write_result(ctid_file, loaded)
    LOGGER.info(f" write_split_result b{batch} {datetime.now() - start_time}")
    return batch


###############################################################################


def has_ip(pkt):
    return isinstance(pkt.data, dpkt.ip.IP)


def to_ip(iter):
    return f"{iter[0]}.{iter[1]}.{iter[2]}.{iter[3]}"


def process_file(file, ips_to_ctids):
    def _in_time_range(ts, start=WINDOW_START, end=WINDOW_END):
        dt = parser.isoparse(ts)
        return start <= dt and dt < end

    def _get_output(file):
        cmd_bzip2 = CMD_BZIP2.substitute(file=file)
        # cmd = f"{cmd_bzip2} | {CMD_TCPDUMP} | {CMD_AWK} | {CMD_SED}"
        cmd = f"{cmd_bzip2} | {CMD_TCPDUMP}"
        # print(cmd)
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.stdout.decode("utf-8")

    def _process_line(ports, ips_to_ctids, line):
        if len(line) == 0:
            return
        split = line.split(" ")
        ts = " ".join(split[0:2])
        try:
            if not _in_time_range(ts):
                return
        except ValueError:  # e.g. 'packet is too short'
            # print(f"    err: {line}")
            return
        date = split[0]
        sip_port = split[3]
        dip_port = split[5]
        if dip_port[-1] == ":":
            dip_port = dip_port[:-1]
        sip = sip_port[: sip_port.rfind(".")]
        dip = dip_port[: dip_port.rfind(".")]
        dport = dip_port[dip_port.rfind(".") + 1 :]
        ctid = ips_to_ctids.get(dip, None)
        ctid = "none" if ctid is None else str(ctid)
        if ctid not in ports:
            ports[ctid] = {}
        if date not in ports[ctid]:
            ports[ctid][date] = dict(
                dport=defaultdict(int),
                transport=defaultdict(int),
                tcp_syn=0,  # for compatibility with other func
                senders=set(),
            )
        if "Flags" in line:
            transport = "tcp"
        else:
            transport = "udp"
        ports[ctid][date]["dport"][str(dport)] += 1
        ports[ctid][date]["transport"][str(transport)] += 1
        ports[ctid][date]["senders"].add(sip)

    ports = {}
    output = _get_output(file)
    for line in output.split("\n"):
        _process_line(ports, ips_to_ctids, line)
    for ctid in ports:
        for date in ports[ctid]:
            ports[ctid][date]["senders"] = list(ports[ctid][date]["senders"])
    return ports


# def process_file(file, ips_to_ctids):
#     def _in_time_range(ts, start=WINDOW_START, end=WINDOW_END):
#         dt = datetime.utcfromtimestamp(ts)
#         return start <= dt and dt < end

#     def _is_inbound(pkt):
#         dst = to_ip(pkt.data.dst)
#         return dst.find("130.245") == 0

#     def _known_transport_protocol(pkt):
#         keep = isinstance(pkt.data.data, dpkt.tcp.TCP)
#         keep = keep or isinstance(pkt.data.data, dpkt.udp.UDP)
#         return keep

#     def _is_tcp_syn(pkt):
#         keep = 0
#         if isinstance(pkt.data.data, dpkt.tcp.TCP):
#             tcp = pkt.data.data
#             keep = tcp.flags & dpkt.tcp.TH_SYN
#         return keep > 0

#     def _get_ctr_transport_port(pkt, ips_to_ctids):
#         dst = to_ip(pkt.ip.dst)
#         dport = pkt.data.data.dport
#         ctid = ips_to_ctids.get(dst, None)
#         _type = None
#         if isinstance(pkt.data.data, dpkt.tcp.TCP):
#             _type = "tcp"
#         elif isinstance(pkt.data.data, dpkt.udp.UDP):
#             _type = "udp"
#         else:
#             raise NotImplementedError(f"unhandled transport protocol")
#         return ctid, _type, dport

#     ports = {}
#     with get_pcap_rdr(file) as rdr:
#         for ts, buf in rdr:
#             if not _in_time_range(ts):
#                 continue
#             eth = dpkt.ethernet.Ethernet(buf)
#             sll = dpkt.sll.SLL(buf)
#             pkt = eth if has_ip(eth) else sll
#             if not has_ip(pkt):
#                 continue
#             if not _known_transport_protocol(pkt):
#                 continue
#             if not _is_inbound(pkt):
#                 continue
#             date = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
#             src = to_ip(pkt.data.src)
#             ctid, transport, dport = _get_ctr_transport_port(pkt, ips_to_ctids)
#             tcp_syn = _is_tcp_syn(pkt)
#             ctid = "none" if ctid is None else str(ctid)
#             if ctid not in ports:
#                 ports[ctid] = {}
#             if date not in ports[ctid]:
#                 ports[ctid][date] = dict(
#                     dport=defaultdict(int),
#                     transport=defaultdict(int),
#                     tcp_syn=0,
#                     senders=set(),
#                 )
#             ports[ctid][date]["dport"][str(dport)] += 1
#             ports[ctid][date]["transport"][str(transport)] += 1
#             if tcp_syn:
#                 ports[ctid][date]["tcp_syn"] += 1
#             ports[ctid][date]["senders"].add(src)
#     for ctid in ports:
#         for date in ports[ctid]:
#             ports[ctid][date]["senders"] = list(ports[ctid][date]["senders"])
#     return ports


###############################################################################
def get_ips_to_ctids(ctrs):
    mapping = {}
    for ctid, ctid_info in ctrs.items():
        ip = ctid_info["ip"]
        mapping[ip] = ctid
    return mapping


def scan_ports():
    def _get_future(_exec, file, ips_to_ctids):
        return _exec.submit(process_file, file, ips_to_ctids)

    def _get_future_serialize(s_exec, results, batch):
        return s_exec.submit(write_split_result, RES_DATA_DIR, results, batch)

    def _yield_batched_files(files, processed_files, n):
        batch = []
        for f in files:
            if len(batch) == n:
                yield batch
                batch = []
            if f not in processed_files:
                batch.append(f)
        if len(batch) > 0:
            yield batch

    def _wait_for_finished_writes(future_to_s_batch, processed_files):
        for s_future in cfutures.as_completed(future_to_s_batch):
            s_batch_info = future_to_s_batch[s_future]
            s_batch = s_batch_info["batch"]
            s_batch_files = s_batch_info["files"]
            try:
                s_future.result()  # wait for completion
            except Exception:
                LOGGER.warning(f"  err with writing batch results {s_batch}: {s_batch_files}")
                traceback.print_exc(file=sys.stderr)
            processed_files.update(s_batch_files)
        future_to_s_batch.clear()  # ensure 1 write job at a time
        write_processed_files(processed_files)

    def _process_files(executor, s_exec, files, processed_files, ips_to_ctids):
        num_files = 0
        num_errs = 0
        killer = utils.GracefulKiller()
        batches = _yield_batched_files(files, processed_files, n=BATCH_SIZE)
        future_to_s_batch = {}
        for batch_idx, batch in enumerate(batches):
            LOGGER.debug(f" batch {batch_idx}...")
            results = {}  # only hold batch results
            batch_results = []
            batch_files = []
            future_to_file = {
                _get_future(executor, file, ips_to_ctids): file
                for file in batch
                if file not in processed_files
            }

            # process batches
            for future in cfutures.as_completed(future_to_file):
                file = future_to_file[future]
                ports = {}
                try:
                    ports = future.result()
                except Exception:
                    num_errs += 1
                    LOGGER.warning(f"  err with future.result {file}")
                    traceback.print_exc(file=sys.stderr)
                if len(ports) > 0:
                    batch_results.append(ports)
                batch_files.append(file)
                num_files += 1
                LOGGER.info(f"  {num_files} {num_errs} ({len(ports)} ctrs) {Path(file).name}")
            _wait_for_finished_writes(future_to_s_batch, processed_files)

            # check if scanning should stop
            if killer.kill_now:
                LOGGER.warning(f"Caught SIGINT/SIGTERM. Finished batch & exiting...")
                return num_files, num_errs

            # submit a write job
            for ports in batch_results:
                update_results(results, ports)
            batch_info = {
                "batch": batch_idx,
                "files": batch_files,
            }
            s_future = _get_future_serialize(s_exec, results, batch_idx)
            future_to_s_batch[s_future] = batch_info
        _wait_for_finished_writes(future_to_s_batch, processed_files)
        return num_files, num_errs

    LOGGER.info(f"Aggregating inbound port statistics...")
    start_time = datetime.now()
    files = get_files()
    # files = [next(files) for _ in range(5)]
    processed_files = load_processed_files()
    ips_to_ctids = get_ips_to_ctids(CTRS)
    with cfutures.ProcessPoolExecutor(max_workers=1) as s_exec:
        with cfutures.ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            LOGGER.info(f"Started executor...")
            num_files, num_errs = _process_files(
                executor, s_exec, files, processed_files, ips_to_ctids
            )
            LOGGER.info(
                f"Processed {num_files}, {num_errs} files in {datetime.now() - start_time}..."
            )


###############################################################################
# PORT ANALYSIS


def filter_reg_dates(results):
    filtered = defaultdict(dict)
    for ctid in results:
        in_window = [
            ctid_date
            for ctid_date in results[ctid].keys()
            if datetime.strptime(ctid_date, "%Y-%m-%d") < FILTER_END
        ]
        if int(ctid) not in PLACEBOS:
            ctid_reg_date = CTRS[int(ctid)]["reg_date"]
            if ctid_reg_date is None:
                print(f"ports: no reg_date found for {ctid}")
            else:
                in_window = [
                    ctid_date
                    for ctid_date in in_window
                    if datetime.strptime(ctid_date, "%Y-%m-%d") >= ctid_reg_date
                ]
        for date in in_window:
            filtered[ctid][date] = results[ctid][date]
    return filtered


def aggregate_ctid_ports(results):
    def _update_agg_ctid(agg_ctid, ctid_date_info):
        dict_keys = ["dport", "transport"]
        int_keys = ["tcp_syn"]
        set_keys = ["senders"]
        for _key in dict_keys:
            for val, num in ctid_date_info[_key].items():
                agg_ctid[_key][val] += num
        for _key in int_keys:
            agg_ctid[_key] += ctid_date_info[_key]
        for _key in set_keys:
            agg_ctid[_key].update(ctid_date_info[_key])

    aggregated = {}
    for ctid in results:
        agg_ctid = dict(
            dport=defaultdict(int),
            transport=defaultdict(int),
            tcp_syn=0,
            senders=set(),
        )
        for _, ctid_date_info in results[ctid].items():
            _update_agg_ctid(agg_ctid, ctid_date_info)
        agg_ctid["num_senders"] = len(agg_ctid["senders"])
        del agg_ctid["senders"]
        aggregated[ctid] = agg_ctid
    return aggregated


def get_top_n_ports_from_data(agg_data, n=DEFAULT_TOP_N):
    top_n = {}
    for ctid in agg_data:
        c = Counter(agg_data[ctid]["dport"])
        top_n[ctid] = c.most_common(n)
    return top_n


# def get_nth_popular_port(top_n, n=0):
#     nth_popular = [top_n[ctid][n] for ctid in top_n]
#     return nth_popular


def get_top_n_ctid_ports(ctid):
    ctid_res = load_split_results(ctids=[str(ctid)], types=["data", "headers"])
    ctid_res = filter_reg_dates(ctid_res)
    ctid_agg_data = aggregate_ctid_ports(ctid_res)
    return get_top_n_ports_from_data(ctid_agg_data)


def get_all_top_n_ports(ctids):
    top_n = {}
    for ctid in ctids:
        ctid_top_n = get_top_n_ctid_ports(str(ctid))
        print(f"  {ctid_top_n}")
        top_n.update(ctid_top_n)
    return top_n


###############################################################################
# HEATMAP


def pairwise_jaccard(top_n, ctids=None, normalized_idx=False):
    ctrs = list(sorted(top_n.keys())) if ctids is None else ctids
    rows = []
    scores = defaultdict(float)
    for ctr1 in ctrs:
        row = []
        ports1 = [port_val[0] for port_val in top_n[ctr1]]
        for ctr2 in ctrs:
            _tuple1 = (ctr1, ctr2)
            _tuple2 = (ctr2, ctr1)
            key = _tuple2 if _tuple2 in scores else _tuple1
            if key in scores:
                score = scores[key]
            else:
                ports2 = [port_val[0] for port_val in top_n[ctr2]]
                score = jaccard_score(ports1, ports2, average="weighted")
                scores[key] = score
            row.append(score)
        rows.append(row)
    idx = [i + 1 for i in range(len(ctrs))] if normalized_idx else ctrs
    jaccard = pd.DataFrame(rows, columns=idx, index=idx)
    return jaccard


def plot_heatmap():
    LOGGER.info("plot_heatmap...")
    ctid_split = [PLACEBOS, NONPLACEBOS, CTRS]
    filenames = [
        "heatmap-jaccard-ports-placebos.png",
        "heatmap-jaccard-ports-nonplacebos.png",
        "heatmap-jaccard-ports-split.png",
    ]
    heatmap_ctids = [None, None]
    placebo_ids = [str(_id) for _id in PLACEBOS]
    nonplacebo_ids = [str(_id) for _id in NONPLACEBOS]
    heatmap_ctids.append([*placebo_ids, *nonplacebo_ids])

    ctid_split = [ctid_split[-1]]
    filenames = [filenames[-1]]
    heatmap_ctids = [heatmap_ctids[-1]]
    for idx, ctids in enumerate(ctid_split):
        top_n = get_all_top_n_ports(ctids)
        jaccard = pairwise_jaccard(top_n, ctids=heatmap_ctids[idx], normalized_idx=True)
        ax = sns.heatmap(jaccard, cmap=sns.cm.rocket_r)
        ax.set_title("Jaccard Similarity Heatmap")
        plt.savefig(PLOT_DIR / filenames[idx])
        plt.clf()


###############################################################################


def get_high_traffic_ports():
    nonplacebo_ids = [str(_id) for _id in NONPLACEBOS]
    top_n = get_all_top_n_ports(nonplacebo_ids)
    high_traffic_top_n = {}
    for ctid, port_info in top_n.items():
        if port_info[0][1] > 10_000_000:
            high_traffic_top_n[ctid] = port_info


###############################################################################
# TIME SERIES


def plot_time_ports():
    LOGGER.info("plot_time_ports...")
    port_fmts = {
        "80": "o-",
        "443": "v--",
        "22": "^-.",
        "23": "<:",
        "21": ">-",
        "8000": "s--",
        "53": "p-.",
        "6600": "x:",
        "25": "D-",
        "465": "+--",
    }
    port_axes = {
        "80": 0,
        "443": 0,
        "22": 0,
        "23": 0,
        "21": 0,
        "8000": 1,
        "53": 1,
        "6600": 1,
        "25": 1,
        "465": 1,
    }
    reqs = defaultdict(lambda: defaultdict(int))
    for ctid in [str(_id) for _id in NONPLACEBOS]:
        ctid_res = load_split_results(ctids=[ctid], types=["data", "headers"])
        ctid_res = filter_reg_dates(ctid_res)
        for date in ctid_res[ctid]:
            for port in port_fmts:
                reqs[port][date] += ctid_res[ctid][date]["dport"].get(port, 0)
    del ctid_res
    print(f"req.keys: {reqs.keys()}")
    sum_reqs = defaultdict(int)
    for port in port_fmts:
        for _, num in reqs[port].items():
            sum_reqs[port] += num
    print(f"sum_reqs: {sum_reqs}")
    cols = ["date", "total"]
    port_dfs = {}
    for port in port_fmts:
        rows = []
        for date, num in reqs[port].items():
            rows.append([date, num])
        port_df = pd.DataFrame(rows, columns=cols)
        port_df.date = pd.to_datetime(port_df.date)
        port_dfs[port] = port_df

    _, axes = plt.subplots(1, 2, sharey=True)
    for port in port_fmts:
        port_df = port_dfs[port]
        port_fmt = port_fmts[port]
        ax_idx = port_axes[port]
        axes[ax_idx].plot(
            port_df.date, port_df.total, port_fmt, label=port, markevery=10, markersize=5
        )

    axes[0].set_ylabel("Number of Inbound Packets")
    ax_titles = ["Honeypot Service Traffic", "Non-Honeypot Service Traffic"]
    for idx, ax in enumerate(axes):
        ax.set_yscale("log")
        ax.grid(True)
        # ax.set_xlabel("Month")    # unnecessary
        ax.set_title(ax_titles[idx])
        ax.legend(loc="best")
        # ax.legend(loc="center left", bbox_to_anchor=(1, 0.5))
        # ax.set_xticklabels(ax.get_xticks(), rotation=45)
        ax.xaxis.set_major_locator(MonthLocator())
        ax.xaxis.set_major_formatter(DateFormatter("%b"))

    plt.tight_layout()
    plt.savefig(PLOT_DIR / "time-ports.png", facecolor="white")
    plt.clf()
    return port_dfs


def get_ctid_totals(ctids):
    totals = defaultdict(dict)
    for ctid in ctids:
        totals[ctid]["pkts"] = 0
        totals[ctid]["senders"] = set()
        ctid_res = load_split_results(ctids=[str(ctid)], types=["data", "headers"])
        ctid_res = filter_reg_dates(ctid_res)
        for date in ctid_res[ctid]:
            totals[ctid]["pkts"] += sum(ctid_res[ctid][date]["dport"].values())
            totals[ctid]["senders"].update(ctid_res[ctid][date]["senders"])
    rows = []
    cols = ["ctid", "total", "num_ips"]
    for ctid, ctid_info in totals.items():
        pkts = ctid_info["pkts"]
        senders = ctid_info["senders"]
        rows.append([ctid, pkts, len(senders)])
    return pd.DataFrame(rows, columns=cols)


def bucket_domains():
    def _apply_bucket(x, buckets):
        if x < buckets[0]:
            return 0
        elif buckets[0] <= x and x < buckets[1]:
            return 1
        else:
            return 2

    df = get_ctid_totals([str(_id) for _id in NONPLACEBOS])
    buckets = np.percentile(df.total, [50, 90])
    df["bucket"] = df.total.apply(_apply_bucket, args=(buckets,))
    df.to_csv(BUCKETS_FILE, index=False)
    return df


def plot_time_buckets():
    def _get_srvc_time_bucket_data():
        import plot_time_series

        time_df = plot_time_series.get_df(plot_time_series.DATA_FILE)
        labels, fmts, data = plot_time_series.plot_time_traffic_buckets(time_df)
        print(f"  got plot_time_series data")
        return labels, fmts, data

    def _add_overall_bkt(bkt_dfs, overall_bkt_num=1.5):
        df = pd.concat([bkt_dfs[0], bkt_dfs[1], bkt_dfs[2]])
        dates = sorted(df.date.unique())
        overall_bkt = []
        for date in dates:
            tmp = df[df.date == date]
            metric = tmp.total.mean()
            overall_bkt.append([date, metric])
        overall_bkt = pd.DataFrame(overall_bkt, columns=["date", "total"])
        overall_bkt = overall_bkt.astype(
            {
                "date": "datetime64[ns]",
                "total": "int64",
            }
        )
        bkt_dfs[overall_bkt_num] = overall_bkt
        return bkt_dfs

    LOGGER.info("plot_time_buckets...")
    _, _, srvc_data = _get_srvc_time_bucket_data()

    buckets = pd.read_csv(BUCKETS_FILE)
    max_ctid = buckets.sort_values(by=["total"], ascending=False).iloc[0].ctid
    print(f"  max_ctid {max_ctid}")
    buckets.loc[buckets.ctid == max_ctid, "bucket"] = 3
    bkts = {}
    for row in buckets.itertuples():
        bkts[str(row.ctid)] = row.bucket

    bkt_labels = {
        3: "Max $[100,100)$",
        2: "High $[90,100)$",
        1.5: "Overall (excluding max)",
        1: "Medium $[50,90)$",
        0: "Low $[0,50)$",
    }
    bkt_fmts = {
        3: ".-",
        2: "o-",
        1.5: "v-",
        1: "^-",
        0: "<-",
    }

    cols = ["date", "total"]
    dtype = {"date": "datetime64[ns]", "total": "int64"}
    bkt_reqs = defaultdict(list)
    for ctid in [str(_id) for _id in NONPLACEBOS]:
        ctid_res = load_split_results(ctids=[str(ctid)], types=["data", "headers"])
        ctid_res = filter_reg_dates(ctid_res)
        ctid_bkt = bkts[ctid]
        for date in ctid_res[ctid]:
            row = [date, sum(ctid_res[ctid][date]["dport"].values())]
            bkt_reqs[ctid_bkt].append(row)
    bkt_dfs = {bkt: pd.DataFrame(rows, columns=cols) for bkt, rows in bkt_reqs.items()}
    bkt_dfs = {
        bkt: df.astype(dtype).groupby(by="date").mean().reset_index()[["date", "total"]]
        for bkt, df in bkt_dfs.items()
    }
    bkt_dfs = _add_overall_bkt(bkt_dfs)

    _, axes = plt.subplots(1, 2, sharey=True)
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    for idx, (bkt, label) in enumerate(bkt_labels.items()):
        df = bkt_dfs[bkt]
        axes[0].plot(df.date, df.total, bkt_fmts[bkt], color=colors[idx], label=label, markevery=10)
    for idx, bkt_data in enumerate(srvc_data):
        labels = list(bkt_labels.values())
        fmts = list(bkt_fmts.values())
        axes[1].plot(
            bkt_data.date,
            bkt_data.total,
            fmts[idx],
            color=colors[idx],
            label=labels[idx],
            markevery=10,
        )
    for ax in axes:
        ax.set_yscale("log")
        ax.grid(True)
        ax.xaxis.set_major_locator(MonthLocator())
        ax.xaxis.set_major_formatter(DateFormatter("%b"))
        # ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=4)
    handles, labels = ax.get_legend_handles_labels()
    lgd = plt.legend(handles, labels, loc="upper center", bbox_to_anchor=(-0.25, -0.1), ncol=3)
    # lgd = plt.legend(handles, labels, loc="lower center", ncol=3)
    axes[0].set_ylabel("Average Number of Inbound Packets")
    axes[0].set_title("By Packets")
    axes[1].set_ylabel("Average Number of Inbound Requests")
    axes[1].set_title("By Honeypot Service Log")

    # sort both labels and handles by labels
    # handles, labels = ax.get_legend_handles_labels()
    # labels, handles = zip(*sorted(zip(labels, handles), key=lambda t: t[0]))
    # ax.legend(handles, labels, loc="best")
    # ax.legend(loc="best")
    # ax.legend(loc="center left", bbox_to_anchor=(1, 0.5), ncol=2)
    # plt.tight_layout()
    plt.savefig(
        PLOT_DIR / "time-port_bkts.png",
        facecolor="white",
        bbox_extra_artists=(lgd,),
        bbox_inches="tight",
    )
    plt.clf()
    return bkt_labels, bkt_fmts, bkt_dfs, srvc_data


# def ips_tagged_user(batch, ips_info):
#     new_ips = [ip for ip in batch if ip not in ips_info]
#     num_trusted_old = len([ip for ip in batch if ip in ips_info and ips_info[ip]])
#     search = es_utils.init_query(QueryEnum.SEARCH, "ips-nginx-access", filter_time=False)
#     query = Q(
#         "bool",
#         filter=[Q("exists", field=es_utils.USER_TAGS_FIELD)],
#         must_not=[Q("exists", field=es_utils.BOT_TAGS_FIELD)],
#         should=[Q("term", ip=ip) for ip in new_ips],
#         minimum_should_match=1,
#     )
#     search = search.query(query)
#     num_trusted_new = 0
#     for hit in search.scan():
#         ip = hit.ip
#         ips_info[ip] = True
#         num_trusted_new += 1
#     return num_trusted_new + num_trusted_old


def process_ctid_ips_tagged_trust(ctid, ips_info):
    ctid_trust = {}
    ctid_reg_date = NONPLACEBOS[int(ctid)]["reg_date"]
    if ctid_reg_date is not None and ctid_reg_date < WINDOW_START:
        return ctid_trust
    ctid_res = load_split_results(ctids=[ctid], types=["data", "headers"])
    ctid_res = filter_reg_dates(ctid_res)
    for date in ctid_res[ctid]:
        ips = ctid_res[ctid][date]["senders"]
        num_trusted = sum([1 if ip in ips_info else 0 for ip in ips])
        ctid_trust[date] = num_trusted
    return ctid_trust


def process_ctid_nonhoney_res_trust(ctids_ports, ctid):
    ctid_trust = {}
    ctid_res = load_split_results(
        ctids=[ctid], types=["non-http"], update_ctid_func=update_ctid_results_nonhoney
    )
    ctid_res = filter_reg_dates(ctid_res)
    for port in ctids_ports[ctid]:
        for date in ctid_res[ctid]:
            if date not in ctid_trust:
                ctid_trust[date] = defaultdict(int)
            port_info = ctid_res[ctid][date]["dport"].get(port, dict())
            ips = port_info.keys()
            num_ips = len(ips)
            ctid_trust[date][port] += num_ips
    return ctid_trust


def plot_time_trust():
    def _get_future(executor, ctid, ips_info):
        return executor.submit(process_ctid_ips_tagged_trust, ctid, ips_info)

    def _get_future_nonhoney(executor, ctids_ports, ctid):
        return executor.submit(process_ctid_nonhoney_res_trust, ctids_ports, ctid)

    def _get_ips_info():
        search = es_utils.init_query(QueryEnum.SEARCH, "ips-nginx-access", filter_time=False)
        query = Q(
            "bool",
            filter=[Q("exists", field=es_utils.USER_TAGS_FIELD)],
            must_not=[Q("exists", field=es_utils.BOT_TAGS_FIELD)],
        )
        search = search.query(query)
        ips_info = set()
        start_time = datetime.now()
        for hit in search.scan():
            ips_info.add(hit.ip)
        print(f"  got {len(ips_info)} trusted ips_info in {datetime.now() - start_time}")
        return ips_info

    def _get_top_trust_ctids():
        # nonplacebo_totals = get_ctid_totals([str(_id) for _id in NONPLACEBOS])
        # nonplacebo_totals = nonplacebo_totals.sort_values(by=["num_ips"], ascending=False)
        # top_n = nonplacebo_totals[:n].ctid.tolist()
        # ipv6tracker, labstats, avantmobile, facecommute, gbox-data, tianxingmeng, km-sea
        # top_n = ["657", "837", "833", "710", "795", "845", "848"]
        top_n = ["837", "657", "833", "845", "710", "673", "688", "630"]
        return top_n

    # def _get_top_nonhttp_ports():
    #     ctids_ports = {
    #         "845": ["8000", "6600"],
    #         "675": ["53"],
    #         "679": ["53"],
    #         "664": ["25"],
    #         "678": ["53"],
    #         "687": ["53"],
    #         "730": ["53"],
    #     }
    #     return ctids_ports

    def _get_honey_df(_file):
        if _file.exists():
            df = pd.read_csv(str(_file))
        else:
            cols = ["ctid", "srvc", "date", "total"]
            rows = []
            ips_info = _get_ips_info()
            with cfutures.ProcessPoolExecutor(max_workers=1) as executor:
                ctids = _get_top_trust_ctids()
                future_to_ctid = {_get_future(executor, ctid, ips_info): ctid for ctid in ctids}
                for future in cfutures.as_completed(future_to_ctid):
                    ctid = future_to_ctid[future]
                    ctid_res = {}
                    try:
                        ctid_res = future.result()
                    except Exception:
                        print(f"  err with ctid {ctid}")
                        traceback.print_exc(file=sys.stderr)
                    print(f"  ctid {ctid} finished")
                    for date, num_trusted in ctid_res.items():
                        row = [ctid, "http(s)", date, num_trusted]
                        rows.append(row)
                ctids_ports = NONHONEY_CTID_PORTS
                future_to_ctid = {
                    _get_future_nonhoney(executor, ctids_ports, ctid): ctid for ctid in ctids_ports
                }
                for future in cfutures.as_completed(future_to_ctid):
                    ctid = future_to_ctid[future]
                    ports = ctids_ports[ctid]
                    ctid_res = {}
                    try:
                        ctid_res = future.result()
                    except Exception:
                        print(f"  err with ctid {ctid}")
                        traceback.print_exc(file=sys.stderr)
                    print(f"  ctid {ctid} finished")
                    for port in ports:
                        ctid_str = f"{ctid} {port}"
                        for date in ctid_res:
                            port_date_num = ctid_res[date].get(port, 0)
                            row = [ctid_str, "non-http", date, port_date_num]
                            rows.append(row)
            df = pd.DataFrame(rows, columns=cols)
            df.to_csv(TIME_TRUST_FILE, index=False, header=True)
        df.date = pd.to_datetime(df.date)
        return df

    LOGGER.info("plot_time_trust...")
    df = _get_honey_df(TIME_TRUST_FILE)
    _, axes = plt.subplots(1, 2, sharey=True, figsize=(7, 5))
    # ax = sns.lineplot(x="date", y="total", hue="ctid", data=df)
    fmts = ["o-", "v--", "^-.", "<:", ">-", "s--", "p-.", "x:"]
    keep_ctids = ["837", "657", "833", "845", "710", "673", "688", "630"]
    keep_ctids.extend(["664", "675", "679"])
    keep_ctids = set(keep_ctids)
    top_n = _get_top_trust_ctids()
    ctids_ports = _get_top_nonhttp_ports()
    ctids_split = [ctids_ports, top_n]
    srvcs = ["non-http", "http(s)"]
    for idx_srvc, srvc in enumerate(srvcs):
        srvc_df = df[df.srvc == srvc]
        ax = axes[idx_srvc]
        ctids = ctids_split[idx_srvc]
        srvc_df_ctid_ports = srvc_df.ctid.unique()
        ctid_order = []
        for ctid_1 in ctids:
            for ctid_2 in srvc_df_ctid_ports:
                if ctid_2.find(ctid_1) == 0:
                    ctid_order.append(ctid_2)
        for idx_ctid, ctid_port in enumerate(ctid_order):
            tmp = srvc_df[srvc_df.ctid == ctid_port]
            ctid = ctid_port if ctid_port.find(" ") == -1 else ctid_port.split(" ")[0]
            if ctid not in keep_ctids:
                continue
            port = "" if ctid_port.find(" ") == -1 else ctid_port[ctid_port.find(" ") :]
            domain = CTRS[int(ctid)]["domain"]
            label = f"{domain}{port}"
            fmt = fmts[idx_ctid]
            ax.plot(tmp.date, tmp.total, fmt, label=label, markevery=10)
    for ax in axes:
        ax.grid(True)
        ax.set_yscale("log")
        ax.set_xlabel("")  # empty
        ax.xaxis.set_major_locator(MonthLocator())
        ax.xaxis.set_major_formatter(DateFormatter("%b"))
    axes[0].set_title("Non-Honeypot Ports")
    axes[0].set_ylabel("Number of IPs")
    lgd1 = axes[0].legend(loc="upper center", ncol=1, bbox_to_anchor=(0.5, -0.1))
    # axes[0].legend(loc="lower left", ncol=1, bbox_to_anchor=(0.25, 0))
    axes[1].set_title("All Ports")
    axes[1].set_ylabel("Number of Trust-Tagged IPs")
    lgd2 = axes[1].legend(loc="upper center", ncol=1, bbox_to_anchor=(0.5, -0.1))
    # axes[1].legend(loc="upper center", ncol=1)

    # plt.tight_layout()
    plt.savefig(
        PLOT_DIR / "time-top-trusted.png",
        facecolor="white",
        bbox_extra_artists=(lgd1, lgd2),
        bbox_inches="tight",
    )
    plt.clf()
    return df


###############################################################################


def plot_box_ips():
    n = 10
    LOGGER.info(f"plot_box_ips with n={n}...")
    placebo_totals = get_ctid_totals([str(_id) for _id in PLACEBOS])
    nonplacebo_totals = get_ctid_totals([str(_id) for _id in NONPLACEBOS])
    placebo_totals = placebo_totals.sort_values(by=["num_ips"], ascending=False)
    nonplacebo_totals = nonplacebo_totals.sort_values(by=["num_ips"], ascending=False)
    n_placebos = n
    n_nonplacebos = n
    # n_placebos = int(n * placebo_totals.shape[0])
    # n_nonplacebos = int(n * nonplacebo_totals.shape[0])
    top_placebos = placebo_totals.iloc[:n_placebos].ctid.tolist()
    last_placebos = placebo_totals.iloc[-1 * n_placebos :].ctid.tolist()
    top_nonplacebos = nonplacebo_totals.iloc[:n_nonplacebos].ctid.tolist()
    last_nonplacebos = nonplacebo_totals.iloc[-1 * n_nonplacebos :].ctid.tolist()
    ctid_labels = {
        "Low-Vol. Placebos": last_placebos,
        "High-Vol. Placebos": top_placebos,
        "Low-Vol. Domains": last_nonplacebos,
        "High-Vol. Domains": top_nonplacebos,
    }
    cols = ["label", "mean_daily_num_ips"]
    rows = []
    for label, ctids in ctid_labels.items():
        for ctid in ctids:
            ctid_res = load_split_results(ctids=[ctid], types=["data", "headers"])
            ctid_res = filter_reg_dates(ctid_res)
            ctid_num_senders = []
            for date in ctid_res[ctid]:
                ctid_num_senders.append(len(ctid_res[ctid][date]["senders"]))
            ctid_avg = np.mean(ctid_num_senders)
            row = [label, ctid_avg]
            rows.append(row)
    df = pd.DataFrame(rows, columns=cols)

    _, ax = plt.subplots(nrows=1, ncols=1, figsize=(6.4, 2.4))
    sns.boxplot(x="label", y="mean_daily_num_ips", data=df, ax=ax)
    ax.set_yscale("log")
    ax.set_ylabel("Daily Mean Unique IP Count")
    ax.set_xlabel("")
    # ax.set_xticklabels(df.label.unique().tolist(), rotation=45)

    plt.tight_layout()
    plt.savefig(PLOT_DIR / "box-ips-placebo_vs_nonplacebo.png", facecolor="white")
    plt.clf()
    return df


###############################################################################


def update_ctid_results_nonhoney(r1, r2):
    if len(r1) == 0:
        r1.update(r2)
        return
    for date, r2_date in r2.items():
        if date not in r1:
            r1[date] = r2_date
            continue
        for port, port_info in r2_date["dport"].items():
            if port not in r1[date]:
                r1[date]["dport"][port] = port_info
                continue
            for ip, num_reqs in port_info.items():
                r1[date]["dport"][port][ip] += num_reqs


def process_file_nonhoney(file, ips_to_ctids, ctid_ip_ports):
    def _in_time_range(ts, start=WINDOW_START, end=WINDOW_END):
        dt = parser.isoparse(ts)
        return start <= dt and dt < end

    def _get_output(file, ctid_ip_ports):
        cmd_bzip2 = CMD_BZIP2.substitute(file=file)
        bpf = ""
        for ctid_ip, ports in ctid_ip_ports.items():
            ctid_ports = ""
            for port in ports:
                ctid_ports += f"port {port} or "
            ctid_ports = ctid_ports[: ctid_ports.rfind(" or ")]
            ctid_bpf = f"dst {ctid_ip} and ({ctid_ports})"
            bpf += f"({ctid_bpf}) or "
        bpf = bpf[: bpf.rfind(" or ")]
        cmd_tcpdump = f"tcpdump -tttt -n -r - '{bpf}'"
        cmd = f"{cmd_bzip2} | {cmd_tcpdump}"
        # LOGGER.debug(f"    cmd {cmd}")
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.stdout.decode("utf-8")

    def _process_line(ports, ips_to_ctids, ctid_ip_ports, line):
        if len(line) == 0:
            return
        split = line.split(" ")
        ts = " ".join(split[0:2])
        try:
            if not _in_time_range(ts):
                return
        except ValueError:  # e.g. 'packet is too short'
            # print(f"    err: {line}")
            return
        date = split[0]
        sip_port = split[3]
        dip_port = split[5]
        if dip_port[-1] == ":":
            dip_port = dip_port[:-1]
        sip = sip_port[: sip_port.rfind(".")]
        dip = dip_port[: dip_port.rfind(".")]
        dport = dip_port[dip_port.rfind(".") + 1 :]
        ctid = ips_to_ctids.get(dip, None)
        if ctid is None:
            return
        ctid = str(ctid)
        if dport not in ctid_ip_ports[dip]:  # not of interest
            return
        if ctid not in ports:
            ports[ctid] = {}
        if date not in ports[ctid]:
            ports[ctid][date] = dict(
                dport=defaultdict(dict),
                # transport=defaultdict(int),   # ignore
                # tcp_syn=0,  # ignore
                # senders=set(),    # ignore
            )
        if str(dport) not in ports[ctid][date]["dport"]:
            ports[ctid][date]["dport"][str(dport)] = defaultdict(int)
        ports[ctid][date]["dport"][str(dport)][sip] += 1

    ports = {}
    output = _get_output(file, ctid_ip_ports)
    for line in output.split("\n"):
        _process_line(ports, ips_to_ctids, ctid_ip_ports, line)
    # for ctid in ports:
    #     for date in ports[ctid]:
    #         for port in ports[ctid][date]["dport"]:
    #             ports[ctid][date]["dport"][port]["senders"] = list(
    #                 ports[ctid][date]["dport"][port]["senders"]
    #             )
    return ports


def scan_non_http():
    def _get_ctid_ip_ports(ctids_ports):
        ctid_ip_ports = {}
        for ctid, ports in ctids_ports.items():
            ip = CTRS[int(ctid)]["ip"]
            ctid_ip_ports[ip] = ports
        return ctid_ip_ports

    def _get_future(_exec, file, ips_to_ctids, ctid_ip_ports):
        return _exec.submit(process_file_nonhoney, file, ips_to_ctids, ctid_ip_ports)

    def _get_future_serialize(s_exec, results, batch):
        return s_exec.submit(
            write_split_result,
            results,
            RES_NONHTTP_DIR,
            batch,
            update_ctid_func=update_ctid_results_nonhoney,
        )

    def _yield_batched_files(files, processed_files, n):
        batch = []
        for f in files:
            if len(batch) == n:
                yield batch
                batch = []
            if f not in processed_files:
                batch.append(f)
        if len(batch) > 0:
            yield batch

    def _wait_for_finished_writes(future_to_s_batch, processed_files):
        # wait for finished writes
        for s_future in cfutures.as_completed(future_to_s_batch):
            s_batch_info = future_to_s_batch[s_future]
            s_batch = s_batch_info["batch"]
            s_batch_files = s_batch_info["files"]
            # LOGGER.debug(f"  s_batch_files {s_batch_files}")
            try:
                s_future.result()  # wait for completion
            except Exception:
                LOGGER.warning(f"  err with writing batch results {s_batch}: {s_batch_files}")
                traceback.print_exc(file=sys.stderr)
            processed_files.update(s_batch_files)
        future_to_s_batch.clear()  # ensure 1 write job at a time
        write_processed_files(processed_files, _file=PROCESSED_NONHTTP_FILE)

    def _process_files(executor, s_exec, files, processed_files, ips_to_ctids, ctid_ip_ports):
        num_files = 0
        num_errs = 0
        killer = utils.GracefulKiller()
        batches = _yield_batched_files(files, processed_files, n=BATCH_SIZE)
        future_to_s_batch = {}
        for batch_idx, batch in enumerate(batches):
            LOGGER.debug(f" batch {batch_idx}...")
            results = {}  # only hold batch results
            batch_results = []
            batch_files = []
            future_to_file = {
                _get_future(executor, file, ips_to_ctids, ctid_ip_ports): file
                for file in batch
                if file not in processed_files
            }

            # process batches
            for future in cfutures.as_completed(future_to_file):
                file = future_to_file[future]
                ports = {}
                try:
                    ports = future.result()
                except Exception:
                    num_errs += 1
                    LOGGER.warning(f"  err with future.result {file}")
                    traceback.print_exc(file=sys.stderr)
                if len(ports) > 0:
                    batch_results.append(ports)
                batch_files.append(file)
                num_files += 1
                LOGGER.info(f"  {num_files} {num_errs} ({len(ports)} ctrs) {Path(file).name}")

            _wait_for_finished_writes(future_to_s_batch, processed_files)

            # check if scanning should stop
            if killer.kill_now:
                LOGGER.warning(f"Caught SIGINT/SIGTERM. Finished batch & exiting...")
                return num_files, num_errs

            # submit a write job
            for ports in batch_results:
                update_results(results, ports, update_ctid_func=update_ctid_results_nonhoney)
            batch_info = {
                "batch": batch_idx,
                "files": batch_files,
            }
            s_future = _get_future_serialize(s_exec, results, batch_idx)
            future_to_s_batch[s_future] = batch_info
        _wait_for_finished_writes(future_to_s_batch, processed_files)
        return num_files, num_errs

    LOGGER.info(f"Aggregating inbound non-HTTP port statistics...")
    start_time = datetime.now()
    files = get_files()
    # files = [next(files) for _ in range(2)]
    processed_files = load_processed_files(_file=PROCESSED_NONHTTP_FILE)
    ips_to_ctids = get_ips_to_ctids(CTRS)
    ctids_ports = NONHONEY_CTID_PORTS
    # ctids_ports = {
    #     "845": ["8000", "6600"],
    #     "675": ["53"],
    #     "679": ["53"],
    #     "667": ["53"],
    #     "664": ["25"],
    #     "678": ["53"],
    #     "687": ["53"],
    #     "730": ["53"],
    # }
    ctid_ip_ports = _get_ctid_ip_ports(ctids_ports)
    with cfutures.ProcessPoolExecutor(max_workers=1) as s_exec:
        with cfutures.ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            LOGGER.info(f"Started executor...")
            num_files, num_errs = _process_files(
                executor,
                s_exec,
                files,
                processed_files,
                ips_to_ctids,
                ctid_ip_ports,
            )
            LOGGER.info(
                f"Processed {num_files}, {num_errs} files in {datetime.now() - start_time}..."
            )


def get_nonhoney_table_stats():
    ctids_ports = NONHONEY_CTID_PORTS
    stats = {}
    asndb = utils.get_asndb()
    for ctid, ports in ctids_ports.items():
        ctid_res = load_split_results(
            ctids=[ctid], types=["non-http"], update_ctid_func=update_ctid_results_nonhoney
        )
        ctid_res = filter_reg_dates(ctid_res)
        for port in ports:
            ctid_stats = dict(
                num_pkts=0,
                num_ips=0,
                num_asns=0,
                num_unknown_asns=0,
                ips=set(),
                asns=set(),
            )
            for date in ctid_res[ctid]:
                port_info = ctid_res[ctid][date]["dport"].get(port, defaultdict(int))
                ips = port_info.keys()
                num_pkts = sum(port_info.values())
                ctid_stats["ips"].update(ips)
                ctid_stats["num_pkts"] += num_pkts
            for ip in ctid_stats["ips"]:
                ip_asn = 1
                try:
                    ip_asn = asndb.asn(ip).autonomous_system_number
                except AddressNotFoundError:
                    ctid_stats["num_unknown_asns"] += 1
                ctid_stats["asns"].add(ip_asn)
            ctid_stats["num_ips"] = len(ctid_stats["ips"])
            ctid_stats["num_asns"] = len(ctid_stats["asns"])
            del ctid_stats["ips"]
            del ctid_stats["asns"]
            ctid_port = f"{ctid} {port}"
            stats[ctid_port] = ctid_stats
            print(f"{ctid_port} {ctid_stats}")

    for ctid, ports in ctids_ports.items():
        ctid_res = load_split_results(
            ctids=[ctid],
            types=["headers", "data"],
        )
        ctid_res = filter_reg_dates(ctid_res)
        for port in ports:
            port_pkts = 0
            for date in ctid_res[ctid]:
                date_pkts = ctid_res[ctid][date]["dport"].get(port, 0)
                port_pkts += date_pkts
            ctid_port = f"{ctid} {port}"
            stats[ctid_port]["num_pkts"] = port_pkts
            print(f"{ctid_port} {stats[ctid_port]}")
    return stats


###############################################################################


def main():
    get_port_stats = False
    scan_nonhttp = True
    # if get_port_stats:
    #     scan_ports()
    # if scan_nonhttp:
    #     scan_non_http()
    plot_heatmap()
    # plot_time_ports()
    # plot_time_buckets()
    # plot_box_ips()
    # plot_time_trust()


if __name__ == "__main__":
    main()