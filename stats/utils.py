import json
import logging
import sys

# import pdb


CONFIG_FILE = "/home/jso/repos/rt_expired/stats/config.json"
CONTAINERS_FILE = "/home/jso/repos/rt_expired/data/containers.txt"
PLACEBOS_FILE = "/home/jso/repos/rt_expired/data/placebos.txt"
LOG_FMT = "%(name)s %(levelname)s %(asctime)-15s %(message)s"
LOGGER = None
CONFIG = None


def get_logger(name, filename, level=logging.INFO):
    global LOGGER
    if LOGGER is None:
        logging.basicConfig(filename=filename, format=LOG_FMT, level=level)
        LOGGER = logging.getLogger(name)
        LOGGER.addHandler(logging.StreamHandler(sys.stdout))
    return LOGGER


def get_config():
    global CONFIG
    if CONFIG is None:
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


def save_as_json(obj, path):
    with open(path, "w+") as f:
        json.dump(obj, f)


def get_time_windows(idx_ptrn):
    cfg = get_config()
    windows = cfg["TIME"]["WINDOWS"]
    idx_windows = windows.get(idx_ptrn, windows["DEFAULT"])
    start_window = idx_windows["START"]
    end_window = idx_windows["END"]
    return start_window, end_window