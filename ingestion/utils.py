import csv
import json
import logging
import sys
from pathlib import Path


BASE_DIR = Path("/home/jso/repos/rt_expired")
CONFIG_FILE = BASE_DIR / "ingestion/config.json"
CONTAINERS_FILE = BASE_DIR / "data/containers.txt"
PLACEBOS_FILE = BASE_DIR / "data/placebos.txt"
LOG_FMT = "%(name)s %(levelname)s %(asctime)-15s %(message)s"
LOGGER = None


def get_logger(name, filename, level):
    global LOGGER
    if LOGGER is None:
        logging.basicConfig(filename=filename, format=LOG_FMT, level=level)
        LOGGER = logging.getLogger(name)
        LOGGER.addHandler(logging.StreamHandler(sys.stdout))
    return LOGGER


def load_config():
    with open(CONFIG_FILE) as f:
        CONFIG = json.load(f)
        return CONFIG


def _get_containers(_file):
    ctids = {}
    with open(_file) as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            ctid, ip, domain = line.rstrip().split(" ")
            ctids[int(ctid)] = {"ip": ip, "domain": domain}
    return ctids


def get_containers():
    return _get_containers(CONTAINERS_FILE)


def get_nonplacebos():
    ctrs = get_containers()
    placebos = get_placebos()
    new_ctrs = {ctid: ctrs[ctid] for ctid in ctrs if ctid not in placebos}
    return new_ctrs


def get_placebos():
    return _get_containers(PLACEBOS_FILE)
