# stdlib
import bz2
from contextlib import contextmanager
import concurrent.futures as cfutures
from datetime import datetime
import glob
from pathlib import Path
import pdb
import sys
import traceback

# 3p
import dpkt

# from scapy.utils import PcapReader
# from scapy.layers.inet import IP, TCP

# from scapy.all import *

# proj
import utils

###############################################################################

LOGGER = utils.get_logger("check_mirai")
TCPDUMP_DIR = Path("/mnt/tcpdump")
FILE_GLOBS = [
    TCPDUMP_DIR / "dump-18*.headers.pcap.8*.bz2",  # dump-18_10_13_00_13_23.headers.pcap.82068.bz2
    TCPDUMP_DIR / "dump-18*.headers.pcap.9*.bz2",
    TCPDUMP_DIR / "dump-19*.headers.pcap*bz2",
]
DUMP18_FIRST_IN_RANGE = 82068

IPS_FILE = Path("../data/mirai-like.csv")
PROCESSED_FILES_FILE = Path("../data/processed-tcpdump.txt")
# OUTPUT_FILE = Path("/mnt/analysis_artifacts/rt_expired/mirai-like.csv")
# OUTPUT_DIR = Path("../data/mirai-like")
NUM_WORKERS = 4
BATCH_SIZE = 15 * NUM_WORKERS

TIME_FMT = "%Y-%m-%d"
WINDOW_START = datetime.strptime("2019-08-01", TIME_FMT)
WINDOW_END = datetime.strptime("2019-12-01", TIME_FMT)

###############################################################################


def get_files():
    for file_glob in FILE_GLOBS:
        globber = glob.iglob(str(file_glob))
        for file in globber:
            _yield = "dump-18" not in file
            if not _yield:
                fname = Path(file).name
                num = int(fname.split(".")[-2])
                _yield = num >= DUMP18_FIRST_IN_RANGE
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


def has_tcp(pkt):
    # dpkt
    try:
        return isinstance(pkt.data.data, dpkt.tcp.TCP)
    except AttributeError:
        return False
    # scapy
    # try:
    #     pkt[TCP]
    #     return True
    # except IndexError:
    #     return False


def to_ip(iter):
    return f"{iter[0]}.{iter[1]}.{iter[2]}.{iter[3]}"


def get_nth_byte(num, n):
    nth = (num >> (n * 8)) & 0xFF
    return nth


def get_ip_addr_from_decimal(num):
    ns = [3, 2, 1, 0]
    _bytes = [get_nth_byte(num, n) for n in ns]
    return f"{_bytes[0]}.{_bytes[1]}.{_bytes[2]}.{_bytes[3]}"


def is_mirai_like(pkt):
    # dpkt
    dst = to_ip(pkt.ip.dst)
    seq_num_to_ip = get_ip_addr_from_decimal(pkt.ip.tcp.seq)

    # scapy
    # dst = pkt[IP].dst
    # seq_num_to_ip = get_ip_addr_from_decimal(pkt[TCP].seq)
    mirai_like = dst == seq_num_to_ip
    return mirai_like


###############################################################################


def load_processed_files():
    return set(utils._get_lines(PROCESSED_FILES_FILE))


def write_processed_files(files):
    with open(PROCESSED_FILES_FILE, "w+") as f:
        out = "\n".join(files)
        f.write(out)


def write_result(ips, batch):
    if len(ips) == 0:
        return
    start_time = datetime.now()
    write_cols = not IPS_FILE.exists()
    with open(IPS_FILE, "a+") as f:
        if write_cols:
            cols = "src_ip"
            f.write(f"{cols}\n")
        out = "\n".join(ips)
        f.write(f"{out}\n")
    LOGGER.info(f" write_result b{batch} ({len(ips)}) {datetime.now() - start_time}")


###############################################################################


def _in_time_range(ts, start=WINDOW_START, end=WINDOW_END):
    dt = datetime.utcfromtimestamp(ts)
    return start <= dt and dt < end


def process_file(file):
    file_ips = set()
    with get_pcap_rdr(file) as rdr:
        # dpkt
        # TODO: do we need to consider the time window?
        for ts, buf in rdr:
            if not _in_time_range(ts):
                continue
            eth = dpkt.ethernet.Ethernet(buf)
            if not has_tcp(eth):
                eth = dpkt.sll.SLL(buf)
            if not (has_tcp(eth) and is_mirai_like(eth)):
                continue
            src_ip = to_ip(eth.ip.src)
            file_ips.add(src_ip)
        # scapy
        # for pkt in rdr:
        #     if not (has_tcp(pkt) and is_mirai_like(pkt)):
        #         continue
        #     src_ip = pkt[IP].src
        #     file_ips.add(src_ip)
    return file_ips


def main():
    def _get_future(_exec, file):
        return _exec.submit(process_file, file)

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

    def _process_files(executor, files, processed_files):
        num_files = 0
        num_errs = 0
        num_ips = 0
        killer = utils.GracefulKiller()
        batches = _yield_batched_files(files, processed_files, n=BATCH_SIZE)
        for batch_idx, batch in enumerate(batches):
            batch_ips = set()
            batch_results = []
            batch_files = []
            future_to_file = {
                _get_future(executor, file): file for file in batch if file not in processed_files
            }
            for future in cfutures.as_completed(future_to_file):
                file = future_to_file[future]
                ips = list()
                try:
                    ips = list(future.result())
                except Exception:
                    num_errs += 1
                    LOGGER.warning(f"  err with future.result {file}")
                    traceback.print_exc(file=sys.stderr)
                if len(ips) > 0:
                    batch_results.append(ips)
                batch_files.append(file)
                num_ips += len(ips)
                num_files += 1
                LOGGER.info(f"  {len(ips)} ({num_ips}, {num_files}) IPs {file}")
            for _file in batch_files:
                processed_files.add(_file)
            for ips in batch_results:
                batch_ips.update(ips)
            write_result(list(batch_ips), batch_idx)
            write_processed_files(processed_files)
            if killer.kill_now:
                LOGGER.warning(f"Caught SIGINT/SIGTERM. Finished batch & exiting...")
                return num_files, num_errs, num_ips
        return num_files, num_errs, num_ips

    LOGGER.info(f"Checking for mirai-like inbound TCP packets...")
    files = get_files()
    # files = [next(files)]
    processed_files = load_processed_files()
    num_ips = 0
    num_files = 0
    num_errs = 0
    start_time = datetime.now()
    with cfutures.ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        LOGGER.info(f"Started executor...")
        num_files, num_errs, num_ips = _process_files(executor, files, processed_files)
        LOGGER.info(
            f"Processed {num_files}, {num_errs} files {num_ips} ips in {datetime.now() - start_time}..."
        )


if __name__ == "__main__":
    main()