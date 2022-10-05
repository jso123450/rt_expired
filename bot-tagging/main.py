# stdlib
import argparse
import json
import pdb

# 3p

# proj
from analysis import ctr_status, geoips, ctr_requests, sankey
from services import nginx, ftp_telnet, ssh
import utils
import es_utils


###############################################################################


LOGGER = utils.get_logger("main")
CONFIG = utils.get_config()

SERVICE_TAG_MAPPER = {
    "nginx-access-*": nginx.tag,
    "ftp-*": ftp_telnet.tag_ftp,
    "telnet-*": ftp_telnet.tag_telnet,
    "ssh-*": ssh.tag,
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
    parser.add_argument(
        "--runtime_config",
        type=str,
        dest="runtime_config",
        help="runtime configuration file with parameters",
    )
    return parser.parse_args()


def load_runtime_config(runtime_config):
    if runtime_config is None:
        runtime_config = CONFIG["RUNTIME"]
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
    ip_type = runtime_cfg["ip_type"]
    placebo = ip_type == "placebo"
    if mode == "analysis_index_status":
        ctr_status.get_service_status(runtime_cfg["services"], runtime_cfg["status_file"])
        return
    elif mode == "analysis_plot_index_status":
        ctr_status.plot_service_status(runtime_cfg["services"], runtime_cfg["status_file"])
        return
    for idx_ptrn in runtime_cfg["services"]:
        if mode == "tag" or mode == "scan":
            func_mapper = SERVICE_TAG_MAPPER if mode == "tag" else SERVICE_SCAN_MAPPER
            tags = runtime_cfg["tags"][idx_ptrn]
            init = runtime_cfg["init"][idx_ptrn]
            func = func_mapper[idx_ptrn]
            if mode == "tag":
                func(tags, init=init, placebo=placebo)
            else:
                ret = func(tags)
                for tag_meta in ret:
                    pdb.set_trace()
                    json_dump(tag_meta, "./scan.json")
        elif mode == "analysis_ctr_status":
            ctr_status.analyze(idx_ptrn, runtime_cfg["status_file"])
        elif mode == "analysis_plot_ctr_status":
            ctr_status.plot_ctr_status()
        elif mode == "reindex":
            dst_ip_idx, _ = es_utils.create_ip_index(idx_ptrn)
            srvc = idx_ptrn[: idx_ptrn.rfind("-*")]
            src_ip_idx = f"ips-{srvc}"
            es_utils.reindex_geoip(src_ip_idx, dst_ip_idx)
        elif mode == "analysis_geoips":
            geoips.analyze(idx_ptrn)
        elif mode == "analysis_untagged_ips_ctrs":
            ctr_status.get_untagged_ips_ctrs(idx_ptrn, runtime_cfg["file"])
        elif mode == "analysis_ctr_reqs":
            ctr_requests.analyze(idx_ptrn)
        elif mode == "analysis_sankey":
            sankey.analyze(idx_ptrn)


if __name__ == "__main__":
    main()