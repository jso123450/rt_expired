# stdlib
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, AddressValueError
import json
import logging
import logging.config
from pathlib import Path
import signal
import sys
from urllib.parse import urlparse

# 3p
from elasticsearch_dsl.connections import connections
import pandas as pd
import geoip2.database

###############################################################################

REPO_DIR = Path("~/repos/rt_expired").expanduser()
REPO_DATA_DIR = REPO_DIR / "data"

CONFIG_FILE = REPO_DIR / "bot-tagging/config.json"
CONTAINERS_FILE = REPO_DATA_DIR / "containers.txt"
PLACEBOS_FILE = REPO_DATA_DIR / "placebos.txt"
BOT_ENDPOINTS_FILE = REPO_DATA_DIR / "bot_endpoints.txt.full"
ADDITIONAL_BOT_ENDPOINTS_FILE = REPO_DATA_DIR / "additional_bot_endpoints.txt"
BOT_TRAPS_FILE = REPO_DATA_DIR / "bot_traps.txt"
PATH_TRAVERSALS_FILE = REPO_DATA_DIR / "path_traversal.txt"
SORTED_CTRS_FILE = REPO_DATA_DIR / "sorted.txt"
MIRAI_IPS_FILE = REPO_DATA_DIR / "mirai-like.csv"
BLOCKLISTS_FILE = REPO_DATA_DIR / "blocklists.txt"
RESIDUAL_PATHS_FILE = REPO_DATA_DIR / "residual_paths.json"
DOMAIN_REG_FILE = REPO_DATA_DIR / "domain_order_log.csv"
# IPASN_DB_FILE = REPO_DATA_DIR / "ipasn_20210410.dat.gz"
ASNDB_FILE = REPO_DATA_DIR / "GeoLite2-ASN_20210406/GeoLite2-ASN.mmdb"

CONFIG = None

################################################################################
# config


class _ExcludeErrorsFilter(logging.Filter):
    def filter(self, record):
        """Filters out log messages with log level ERROR (numeric value: 40) or higher."""
        return record.levelno < logging.ERROR


def get_config():
    global CONFIG
    if CONFIG is None:
        with open(CONFIG_FILE) as f:
            CONFIG = json.load(f)
        es_config = CONFIG["ELASTICSEARCH"]
        connections.configure(
            default={
                "hosts": es_config["HOSTS"],
                "timeout": es_config["TIMEOUT"],
                "max_retries": es_config["MAX_RETRIES"],
                "retry_on_timeout": es_config["RETRY_ON_TIMEOUT"],
            }
        )
    config = {
        "version": 1,
        "filters": {"exclude_errors": {"()": _ExcludeErrorsFilter}},
        "formatters": {
            # Modify log message format here or replace with your custom formatter class
            "file_formatter": {"format": CONFIG["LOG"]["FMT"]},
            "stdout_formatter": {"format": CONFIG["LOG"]["FMT"]},
        },
        "handlers": {
            "console_stderr": {
                # Sends log messages with log level ERROR or higher to stderr
                "class": "logging.StreamHandler",
                "level": "ERROR",
                "formatter": "stdout_formatter",
                "stream": sys.stderr,
            },
            "console_stdout": {
                # Sends log messages with INFO <= log level to stdout
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "stdout_formatter",
                "filters": ["exclude_errors"],
                "stream": sys.stdout,
            },
            "file": {
                # Sends all log messages to a file
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "formatter": "file_formatter",
                "filename": CONFIG["LOG"]["FILE"],
                "encoding": "utf8",
            },
        },
        "root": {
            # In general, this should be kept at 'NOTSET'.
            # Otherwise it would interfere with the log levels set for each handler.
            "level": "NOTSET",
            "handlers": ["console_stderr", "console_stdout", "file"],
        },
        "loggers": {
            "main": {},
            "analysis": {},
            "es_utils": {},
            "services_common": {},
            "services_nginx": {},
            "services_ftp_telnet": {},
            "services_ssh": {},
            "status": {},
            "check_mirai": {},
            "one_off": {},
        },
    }
    logging.config.dictConfig(config)
    return CONFIG


def get_logger(name):
    if CONFIG is None:
        get_config()
    return logging.getLogger(name)


################################################################################
# containers


def _get_containers(_file):
    reg = get_domain_reg()
    ctids = {}
    with open(_file) as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            ctid, ip, domain = line.rstrip().split(" ")
            reg_date = None
            cost = None
            if "placebo" not in domain and "-" in domain:
                last_hyphen = domain.rfind("-")
                domain = domain[:last_hyphen] + "." + domain[last_hyphen + 1 :]
            if "placebo" not in domain:
                tmp = reg[reg.item == domain]
                if tmp.shape[0] > 1:
                    print(f"utils: more than one registration for {domain}")
                    reg_date = tmp.iloc[0].date
                    cost = tmp.iloc[0].cost
                elif tmp.shape[0] == 0:
                    print(f"utils: no registration found for {domain}")
                else:
                    reg_date = tmp.iloc[0].date
                    cost = tmp.iloc[0].cost
            ctids[int(ctid)] = {"ip": ip, "domain": domain, "reg_date": reg_date, "cost": cost}
    return ctids


def get_containers():
    return _get_containers(CONTAINERS_FILE)


def get_placebos():
    return _get_containers(PLACEBOS_FILE)


def get_nonplacebos():
    ctrs = get_containers()
    placebos = get_placebos()
    new_ctrs = {ctid: ctrs[ctid] for ctid in ctrs if ctid not in placebos}
    return new_ctrs


def get_domain_reg():
    df = pd.read_csv(DOMAIN_REG_FILE)
    df.date = pd.to_datetime(df.date)
    reg = df[df.item_detail.str.contains("registration")]
    return reg


################################################################################
# reading lines


def count_lines(filename, open_func=open):
    def _make_gen(reader):
        b = reader(1024 * 1024)
        while b:
            yield b
            b = reader(1024 * 1024)

    with open_func(filename, "rb") as f:
        try:
            f_gen = _make_gen(f.raw.read)
        except AttributeError:
            f_gen = _make_gen(f.read)
        return sum(buf.count(b"\n") for buf in f_gen)


def _get_lines(_file, n=0):
    unique_lines = []
    _set = set()
    try:
        with open(_file) as f:
            for idx, line in enumerate(f):
                if idx < n:
                    continue
                stripped = line.rstrip()
                if stripped not in _set:
                    unique_lines.append(stripped)
                    _set.add(stripped)
    except FileNotFoundError:
        pass
    return unique_lines


def get_bot_traps():
    return _get_lines(BOT_TRAPS_FILE)


def get_bot_endpoints():
    return _get_lines(BOT_ENDPOINTS_FILE)


def get_additional_bot_endpoints():
    return _get_lines(ADDITIONAL_BOT_ENDPOINTS_FILE)


def get_path_traversals():
    return _get_lines(PATH_TRAVERSALS_FILE)


def get_sorted_containers():
    return _get_lines(SORTED_CTRS_FILE)


def get_mirai_ips():
    return _get_lines(MIRAI_IPS_FILE, n=1)


def get_blocklists():
    return _get_lines(BLOCKLISTS_FILE, n=1)


def get_residual_paths():
    with open(RESIDUAL_PATHS_FILE, "r") as f:
        return json.load(f)


################################################################################
# iterables


def batch_iterable(iterable, n=100, key=lambda x: x):
    batch = []
    for o in iterable:
        if len(batch) == n:
            yield batch
            batch = []
        batch.append(key(o))
    if len(batch) > 0:
        yield batch


# def save_as_json(obj, path):
#     with open(path, "w+") as f:
#         json.dump(obj, f)


################################################################################
# IPs


def validate_ip(ip):
    try:
        IPv4Address(ip)
        return True
    except AddressValueError:
        pass
    try:
        IPv6Address(ip)
        return True
    except AddressValueError:
        pass
    return False


################################################################################
# URLs


def get_num_query_values(url):
    o = urlparse(url)
    num_query_values = 0
    for kv in o.query.split("&"):
        k_v = kv.split("=")
        if len(k_v) == 2 and len(k_v[1]) > 0:
            num_query_values += 1
    return num_query_values


def get_url_wo_query_values(url):
    o = urlparse(url)
    new_url = ""
    if len(o.scheme) > 0:
        new_url = f"{o.scheme}://{o.netloc}"
    new_url = f"{new_url}/{o.path}" if len(new_url) > 0 else o.path
    if len(o.query) > 0:
        keys = [kv.split("=")[0] for kv in o.query.split("&")]
        keys = [f"{key}=" for key in keys]
        q_wo_values = "&".join(keys)
        new_url = f"{new_url}?{q_wo_values}"
    return new_url


def write_iter_line(file, iter, sep=","):
    with open(file, "a+") as f:
        line = f"{sep.join(iter)}\n"
        f.write(line)


################################################################################
# GRACEFUL EXIT

# https://stackoverflow.com/questions/18499497/how-to-process-sigterm-signal-gracefully
class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        print(f"Caught SIGINT/SIGTERM...")
        self.kill_now = True


################################################################################


def get_asndb():
    return geoip2.database.Reader(ASNDB_FILE)