# stdlib
import argparse
import json
import pdb

# 3p

# proj
import ctr_status
from services import nginx, ftp_telnet  # , ssh
import utils
import es_utils


###############################################################################


LOGGER = utils.get_logger("main", "./logs/main_ftp.log")

SERVICE_TAG_MAPPER = {
    "nginx-access-*": nginx.tag,
    "ftp-*": ftp_telnet.tag_ftp,
    "telnet-*": ftp_telnet.tag_telnet,
    # "ssh-*": ssh.tag,
}

SERVICE_SCAN_MAPPER = {
    "nginx-access-*": nginx.scan,
    "ftp-*": ftp_telnet.scan_ftp,
    "telnet-*": ftp_telnet.scan_telnet,
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


def json_dump(obj, _file):
    with open(_file, "a+") as f:
        f.write(f"{json.dumps(obj)}\n")


###############################################################################


def main():
    args = parse_args()
    runtime_cfg = load_runtime_config(args.runtime_config)
    mode = runtime_cfg["mode"]
    for idx_ptrn in runtime_cfg["services"]:
        if mode == "tag" or mode == "scan":
            func_mapper = SERVICE_TAG_MAPPER if mode == "tag" else SERVICE_SCAN_MAPPER
            tags = runtime_cfg["tags"][idx_ptrn]
            init = runtime_cfg["init"][idx_ptrn]
            func = func_mapper[idx_ptrn]
            if mode == "tag":
                func(tags, init=init)
            else:
                ret = func(tags)
                for tag_meta in ret:
                    pdb.set_trace()
                    json_dump(tag_meta, "./scan.json")
        elif mode == "status":
            ctr_status.get_containers_status(idx_ptrn, runtime_cfg["status_file"])
        elif mode == "plot_status":
            ctr_status.plot_status()


if __name__ == "__main__":
    main()