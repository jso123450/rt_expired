# stdlib
import argparse
import json

# 3p

# proj
import ctr_status
from services import nginx, ftp_telnet
import utils
import es_utils


###############################################################################


LOGGER = utils.get_logger("main", "./logs/main.log")

SERVICE_TAG_MAPPER = {
    "nginx-access-*": nginx.tag,
    "ftp-*": ftp_telnet.tag_ftp,
    "telnet-*": ftp_telnet.tag_telnet,
}
NONPLACEBOS = utils.get_nonplacebos()

###############################################################################


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime_config", type=str, help="config run file with parameters")
    return parser.parse_args()


def load_runtime_config(runtime_config):
    with open(runtime_config, "r") as f:
        return json.load(f)


###############################################################################


def main():
    args = parse_args()
    runtime_cfg = load_runtime_config(args.runtime_config)
    mode = runtime_cfg["mode"]
    for idx_ptrn in runtime_cfg["services"]:
        if mode == "tag":
            tags = runtime_cfg["tags"][idx_ptrn]
            init = runtime_cfg["init"][idx_ptrn]
            func = SERVICE_TAG_MAPPER[idx_ptrn]
            func(tags, init=init)
        elif mode == "status":
            ctr_status.get_containers_status(idx_ptrn, runtime_cfg["status_file"])
        elif mode == "plot_status":
            ctr_status.plot_status()


if __name__ == "__main__":
    main()