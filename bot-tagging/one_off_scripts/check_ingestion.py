from datetime import datetime
import glob
import gzip
import json
from pathlib import Path
import re
import sys
import pdb

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))


from elasticsearch_dsl import A, Q, Search
import pandas as pd
import pytz

from enums import QueryEnum, TagEnum
import utils
import es_utils

GLOBS = {
    "nginx-access-*": "var/log/nginx/access*.gz",
    "telnet-*": "var/log/telnet*.gz",
    "ftp-*": "var/log/ftp*.gz",
    "ssh-*": "home/cowrie/cowrie/log/cowrie.json*.gz",
    "fp-*": "home/najmeh/userFingerprint/fp*.gz",
}
CTRS = utils.get_containers()
LOGGER = utils.get_logger("one_off")

NAS_DIR = Path("/mnt/nas")
DATA_DIR = MAIN_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_FILE = DATA_DIR / "check_ingestion.csv"

PYTZ_UTC = pytz.UTC
SEP_PATH = "/"
SEP_CSV = "|"
WINDOW_FMT = "%Y-%m-%d"
WINDOW_START = PYTZ_UTC.localize(datetime.strptime("2019-08-01", WINDOW_FMT))
WINDOW_END = PYTZ_UTC.localize(datetime.strptime("2019-12-01", WINDOW_FMT))

NGINX_FMT = "\[\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} ?((\+|-|).{4,13})?\]"


def get_line_num_bounds(filename, open_func, _filter, _filter_args):
    start = float("inf")
    end = -1
    with open_func(filename, "r") as f:
        for idx, x in enumerate(f):
            line = x.decode("utf-8") if isinstance(x, bytes) else x
            if _filter(*_filter_args, line):
                start = min(idx, start)
                end = max(idx, end)
    if start == float("inf"):
        start = -1
    return start, end


def parse_timestamp(srvc, line):
    timestamp = ""
    fmt = ""
    if srvc == "nginx":
        start, end = re.search(NGINX_FMT, line).span(0)
        timestamp = line[start + 1 : end - 1]
        fmt = "%d/%b/%Y:%H:%M:%S %z"
    elif srvc == "ssh":
        obj = json.loads(line)
        timestamp = obj["timestamp"]
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    elif srvc == "telnet" or srvc == "ftp":
        start = 0
        end = 19
        timestamp = line[start:end]
        fmt = "%Y-%m-%d %H:%M:%S"
    elif srvc == "fp":
        start = 1
        end = 16
        timestamp = line[start:end]
        fmt = "%Y%m%d-%H%M%S"
    date = None
    try:
        date = datetime.strptime(timestamp, fmt)
        date = PYTZ_UTC.localize(date)
    except ValueError:
        pass
    return date


def get_logs_in_range(srvc, file):
    def is_log_in_range(srvc, line):
        timestamp = parse_timestamp(srvc, line)
        if timestamp is None:
            return False
        return WINDOW_START <= timestamp and timestamp <= WINDOW_END

    start, end = get_line_num_bounds(file, gzip.open, is_log_in_range, (srvc,))
    return start, end


def get_missing_logs(srvc, file, start_log, end_log):
    ctid_path = file[len(str(NAS_DIR)) + 1 :]
    parts = ctid_path.split(SEP_PATH)
    ctid = parts[0]
    path = SEP_PATH + SEP_PATH.join(parts[1:])
    search = es_utils.init_query(QueryEnum.SEARCH, srvc, filter_time=True, ctids=[ctid])
    search = search.query("bool", filter=[Q("term", log__path__keyword=path)])
    line_agg = {"line": A("terms", field="log.line")}
    _generator = es_utils.scan_aggs(search, [line_agg], size=1_000)
    missing = set()
    docs = set([bucket.key.line for bucket in _generator])
    missing = set([i for i in docs if i < start_log or i > end_log])
    return missing


def main():
    cols = ["ctid", "srvc", "file", "num_lines", "num_missing", "missing"]
    utils.write_iter_line(DATA_FILE, cols, sep=SEP_CSV)
    start_idx = 58  # 674
    for idx, ctr in enumerate(CTRS):
        if idx < start_idx:
            continue
        LOGGER.debug(f"idx {idx} ctr {ctr}")
        ctr_dir = NAS_DIR / str(ctr)
        for srvc, glob_ptrn in GLOBS.items():
            LOGGER.debug(f" srvc {srvc}")
            srvc_glob = str(ctr_dir / glob_ptrn)
            files = glob.iglob(srvc_glob)
            num_files = 0
            for idx, file in enumerate(files):
                if (
                    "201908" not in file
                    and "201909" not in file
                    and "201910" not in file
                    and "201911" not in file
                    and "201912" not in file
                ):
                    continue
                if idx % 100 == 0:
                    LOGGER.debug(f"  on file {idx} {file}...")
                start_log, end_log = get_logs_in_range(srvc, file)
                num_lines = end_log - start_log
                missing = get_missing_logs(srvc, file, start_log, end_log)
                num_missing = len(missing)
                if num_lines == 0 or num_missing == 0:
                    continue
                if num_missing > 0:
                    LOGGER.debug(f"  missing {num_missing} in file {file}")
                row = [str(ctr), srvc, file, str(num_lines), str(num_missing), str(missing)]
                utils.write_iter_line(DATA_FILE, row, sep=SEP_CSV)
                num_files += 1
            LOGGER.debug(f" srvc {srvc} found {num_files} files")


if __name__ == "__main__":
    main()
