# stdlib
import json
import logging
from pathlib import Path
import sys

# 3p
from elasticsearch_dsl.connections import connections

###############################################################################

REPO_DIR = Path("~/repos/rt_expired").expanduser()
REPO_DATA_DIR = REPO_DIR / "data"

CONFIG_FILE = REPO_DIR / "bot-tagging/config.json"
CONTAINERS_FILE = REPO_DATA_DIR / "containers.txt"
PLACEBOS_FILE = REPO_DATA_DIR / "placebos.txt"
BOT_ENDPOINTS_FILE = REPO_DATA_DIR / "bot_endpoints.txt.1"
BOT_TRAPS_FILE = REPO_DATA_DIR / "bot_traps.txt"
PATH_TRAVERSALS_FILE = REPO_DATA_DIR / "path_traversal.txt"

CONFIG = None

################################################################################


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
    return CONFIG


def get_logger(name, filename, level=logging.INFO):
    if CONFIG is None:
        get_config()
    logging.basicConfig(format=CONFIG["LOG"]["FMT"], level=level)
    logger = logging.getLogger(name)
    logger.addHandler(logging.FileHandler(filename))
    # logger.addHandler(logging.StreamHandler(sys.stdout))
    return logger


################################################################################


def _get_containers(_file):
    ctids = {}
    with open(_file) as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            ctid, ip, domain = line.rstrip().split(" ")
            if "placebo" not in domain and "-" in domain:
                last_hyphen = domain.rfind("-")
                domain = domain[:last_hyphen] + "." + domain[last_hyphen + 1 :]
            ctids[int(ctid)] = {"ip": ip, "domain": domain}
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


################################################################################


def _get_lines(_file):
    unique_lines = []
    with open(_file) as f:
        lines = f.readlines()
        lines = [line.rstrip() for line in lines]
        lines = set(lines)
        unique_lines.extend(lines)
    return unique_lines


def get_bot_traps():
    return _get_lines(BOT_TRAPS_FILE)


def get_bot_endpoints():
    return _get_lines(BOT_ENDPOINTS_FILE)


def get_path_traversals():
    return _get_lines(PATH_TRAVERSALS_FILE)


################################################################################


def batch_iterable(iterable, n=100):
    batch = []
    for o in iterable:
        if len(batch) == n:
            yield batch
            batch = []
        batch.append(o)
    if len(batch) > 0:
        yield batch


# def save_as_json(obj, path):
#     with open(path, "w+") as f:
#         json.dump(obj, f)