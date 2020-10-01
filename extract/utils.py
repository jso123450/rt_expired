import csv
import json
import logging
import sys


CONFIG_FILE = "/home/jso/repos/rt_expired/extract/config.json"
CONTAINERS_FILE = "/home/jso/repos/rt_expired/data/containers.txt"
PLACEBOS_FILE = "/home/jso/repos/rt_expired/data/placebos.txt"
LOG_FILE = "./log.log"
LOG_FMT = "%(name)s %(levelname)s %(asctime)-15s %(message)s"
LOGGER = None


def get_logger(name, level):
    global LOGGER
    if LOGGER is None:
        logging.basicConfig(filename=LOG_FILE, format=LOG_FMT, level=level)
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
            ctid, domain = line.rstrip().split(" ")
            ctids[int(ctid)] = domain
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
