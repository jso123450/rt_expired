import csv
import json

CONFIG_FILE = "/home/jso/repos/rt_expired/extract/config.json"
CONTAINERS_FILE = "/home/jso/repos/rt_expired/containers.txt"


def load_config():
    with open(CONFIG_FILE) as f:
        CONFIG = json.load(f)
        return CONFIG


def get_containers():
    ctids = {}
    with open(CONTAINERS_FILE) as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            ctid, domain = line.rstrip().split(" ")
            ctids[int(ctid)] = domain
    return ctids
