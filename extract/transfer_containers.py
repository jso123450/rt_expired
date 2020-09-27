# Dependencies
## stdlib
import argparse
import json
import logging
from pathlib import Path
from string import Template
import os
import subprocess
import sys
import time

## proj
import utils

CONFIG = utils.load_config()
CONFIG_SRC = CONFIG["SRC"]
CONFIG_DST = CONFIG["DST"]

# Constants
LOG_FMT = "%(levelname)s %(asctime)-15s %(message)s"
CHUNK_SIZE = 5
## rsync -avP --include='*.gz' --include='*/' --exclude='*' ~/honeyData/vz/root/100 ubuntu@130.245.169.240:/home/ubuntu/data
RSYNC_TEMP = Template(
    f"rsync -avP --include='*.gz' --include='*/' --exclude='*' {CONFIG_SRC['CTR_DIR']}/$ctr $host:$dir"
)
GUNZIP_TEMP = Template(f"gunzip -rf $dir/$ctr/var/log")  # ctr that has not yet been unzipped
RM_CMD = "sudo python3 filebeat_scrubber.py --remove --summary"
FIND_CMD = "find data -type f -name '*.gz' | sort | head -n 1"

logging.basicConfig(
    filename=f"{CONFIG['LOCAL_DIR']}/{CONFIG['TRANSFER_LOG']}", format=LOG_FMT, level=logging.DEBUG
)
logger = logging.getLogger("transfer_containers")
logger.addHandler(logging.StreamHandler(sys.stdout))

# Utils
def get_rsync_cmd(ctr, dst, _dir):
    return RSYNC_TEMP.substitute(ctr=ctr, host=dst, dir=_dir)


def get_gunzip_cmd(ctr, _dir):
    return GUNZIP_TEMP.substitute(ctr=ctr, dir=_dir)


def get_rm_cmd():
    return RM_CMD


def get_find_cmd():
    return FIND_CMD


def get_next_ctr(dst_host):
    cmd = get_find_cmd()
    res = run_ssh(dst_host, cmd, output=True).strip()
    paths = res.split("/")
    return int(paths[1])


def run_ssh(host, cmd, output=False, check=False):
    # stdout = sys.stdout if output else subprocess.DEVNULL
    proc = subprocess.run(["ssh", host, cmd], capture_output=output, check=check)
    if output:
        return proc.stdout.decode("utf-8")
    else:
        return None


def rsync(src_host, dst_config, last_ctr, until, ctrs):
    dst_host = dst_config["HOST"]
    dst_dir = dst_config["CTR_DIR"]
    for idx, ctr in enumerate(ctrs):
        logger.debug(f"rsync'ing ctr {ctr}...{len(ctrs)-idx-1} left")
        rsync_cmd = get_rsync_cmd(ctr, dst_host, dst_dir)
        try:
            logger.debug(f"\t rsync'ing {ctr}: {rsync_cmd}")
            run_ssh(src_host, rsync_cmd, output=False, check=False)
        except subprocess.CalledProcessError as e:
            logger.error(f"\t rsync err {ctr}: {e}")
            continue
        # break


def filebeat_scrub(dst_host):
    rm_cmd = get_rm_cmd()
    logger.debug(f"scrubbing {dst_host}: {rm_cmd}")
    summary = run_ssh(dst_host, rm_cmd, output=True)
    logger.info(summary)


def unzip(dst_config, last_ctr, scrub, ctrs):
    dst_host = dst_config["HOST"]
    dst_dir = dst_config["CTR_DIR"]
    if last_ctr is None:
        next_ctr = get_next_ctr(dst_host)
        logger.debug(f"host {dst_host} gunzip'ing from {next_ctr}")
        ctrs = ctrs[ctrs.index(next_ctr) :]
    ctrs = ctrs[:CHUNK_SIZE]

    for idx, ctr in enumerate(ctrs):
        logger.debug(f"guzip'ing ctr {ctr}...{len(ctrs)-idx-1} left")
        gunzip_cmd = get_gunzip_cmd(ctr, dst_dir)
        try:
            logger.debug(f"\t gunzip'ing {ctr}: {gunzip_cmd}")
            run_ssh(dst_host, gunzip_cmd, output=False, check=False)
        except subprocess.CalledProcessError as e:
            if e.returncode == 2:
                logger.warning(f"\t gunzip warning {ctr}: {e.returncode}")
            else:
                logger.error(f"\t gunzip err {ctr}: {e}")
        # break


def main(dst, last_ctr, transfer, until, scrub, gunzip):
    src_host = CONFIG_SRC["HOST"]
    dst_config = CONFIG_DST[dst]
    dst_host = dst_config["HOST"]
    dst_dir = dst_config["CTR_DIR"]
    ctrs = list(utils.get_containers().keys())
    if last_ctr is not None and last_ctr != -1:
        ctrs = ctrs[ctrs.index(last_ctr) + 1 :]
    if until is not None:
        ctrs = ctrs[: ctrs.index(until) + 1]

    if transfer:
        rsync(src_host, dst_config, last_ctr, until, ctrs)

    if scrub:
        filebeat_scrub(dst_host)

    if gunzip:
        unzip(dst_config, last_ctr, scrub, ctrs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transfer container data.")
    parser.add_argument("dst", type=str)
    parser.add_argument("--last_ctr", type=int)
    parser.add_argument("--until", type=int)
    parser.add_argument("--transfer", dest="transfer", action="store_true")
    parser.add_argument("--no-transfer", dest="transfer", action="store_false")
    parser.add_argument("--scrub", dest="scrub", action="store_true")
    parser.add_argument("--no-scrub", dest="scrub", action="store_false")
    parser.add_argument("--gunzip", dest="gunzip", action="store_true")
    parser.add_argument("--no-gunzip", dest="gunzip", action="store_false")
    parser.set_defaults(transfer=False, scrub=True, gunzip=True)
    args = parser.parse_args()
    main(args.dst, args.last_ctr, args.transfer, args.until, args.scrub, args.gunzip)
