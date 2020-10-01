import json
from pathlib import Path
import subprocess

import pdb

import utils

SHIPPERS = ["rt_shipper_1", "rt_shipper_2", "rt_shipper_3", "rt_shipper_4", "rt_shipper_5"]
FINISHED_PATH = Path("./finished.json")


def get_finished_ctrs(shipper):
    cmd = "cat /home/ubuntu/ingestion_progress.log"
    out = subprocess.run(["ssh", shipper, cmd], capture_output=True).stdout.decode("utf-8")
    ctrs = [int(ctr) for ctr in out.split("\n") if len(ctr) > 0]
    return ctrs


def get_shipper_ctrs(shipper):
    cmd = "ls /home/ubuntu/data"
    out = subprocess.run(["ssh", shipper, cmd], capture_output=True).stdout.decode("utf-8")
    ctrs = [int(ctr) for ctr in out.split("\n") if len(ctr) > 0]
    return ctrs


def write_finished_ctrs(finished):
    with open(FINISHED_PATH, "w+") as f:
        json.dump(finished, f, indent=4)


def get_missing_ctrs(ctrs, shippers):
    shipper_ctrs = []
    for shipper in shippers:
        shipper_ctrs.extend(shippers[shipper])
    return [ctr for ctr in ctrs if ctr not in shipper_ctrs]


def get_finished_placebos(ctrs, finished):
    placebos = []
    for shipper in finished:
        for ctid in finished[shipper]:
            if "placebo" in ctrs[ctid]:
                placebos.append(ctid)
    return placebos


def main():
    shippers = {}
    finished = {}
    total_finished = 0
    total_ctrs = 0
    ctrs = utils.get_containers()
    for shipper in SHIPPERS:
        finished[shipper] = get_finished_ctrs(shipper)
        shipper_ctrs = get_shipper_ctrs(shipper)
        shippers[shipper] = shipper_ctrs
        total_finished += len(finished[shipper])
        total_ctrs += len(shipper_ctrs)
        print(f"  {shipper} finished {len(finished[shipper])}/{len(shipper_ctrs)} containers.")
    placebos = get_finished_placebos(ctrs, finished)
    print(f"Finished {len(placebos)} placebos.")
    print(f"Finished {total_finished}/{total_ctrs} containers.")
    print(f"len(ctrs), total_ctrs {len(ctrs)} {total_ctrs}")
    write_finished_ctrs(finished)

    missing = get_missing_ctrs(ctrs, shippers)
    print(f"Missing {missing}")


if __name__ == "__main__":
    main()