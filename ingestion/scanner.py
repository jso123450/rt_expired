import glob
import os
from pathlib import Path
from string import Template
import subprocess
import tempfile

import pdb

import utils

########################################################

CONFIG = utils.load_config()["SCANNER"]
LOGGER = utils.get_logger("scanner", f"{CONFIG['HOME_DIR']}/{CONFIG['LOG_PATH']}")

SORTED_CTRS_KEY = "SORTED_CTRS_PATH"
PROCESSING_CTRS_KEY = "PROCESSING_CTRS_PATH"
FINISHED_CTRS_KEY = "FINISHED_CTRS_PATH"
HOME_DIR_KEY = "HOME_DIR"
RAW_DIR_KEY = "RAW_DIR"
PROCESS_DIR_KEY = "PROCESS_DIR"
SPACE_THRESHOLD_KEY = "SPACE_THRESHOLD"

########################################################


def get_home_prefix(path):
    return Path(CONFIG[HOME_DIR_KEY]) / path


def get_raw_prefix(path):
    return Path(CONFIG[RAW_DIR_KEY]) / path


########################################################


def get_gunzip_cmd(ctr_path):
    return f"gunzip -rf {ctr_path}"


def get_gunzip_err_cmd(tmpfile):
    return "cat " + tmpfile + " | egrep 'gzip format|unexpected' | awk '{print $2}'"


def get_sort_ctrs_cmd(raw_dir):
    return "du -sh " + raw_dir + "/* | sort -h | awk '{print $2}'"


def get_free_space_cmd():
    return "df -h | grep -w '/dev/vda1' | awk '{print $3}'"


def get_cp_cmd(ctr):
    src = CONFIG[RAW_DIR_KEY]
    dst = get_home_prefix(CONFIG[PROCESS_DIR_KEY])
    cmd = Template(
        f"cd {src} && find $ctr -type f -name '*.gz' -exec cp --parents '{{}}' {dst}/ ';'"
    )
    return cmd.substitute(ctr=ctr)


########################################################


def get_ctrs():
    """ Returns valid containers sorted in ascending order by disk usage. """
    sorted_ctrs_path = get_home_prefix(CONFIG[SORTED_CTRS_KEY])
    ctrs = get_ctrs_from_file(SORTED_CTRS_KEY)
    if len(ctrs) == 0:
        running_containers = utils.get_containers()  # get running containers
        cmd = get_sort_ctrs_cmd(CONFIG[RAW_DIR_KEY])
        res = utils.run_cmd(cmd, output=True)
        ctr_paths = res.strip().split("\n")
        ctrs = [ctr_path.split("/")[-1] for ctr_path in ctr_paths]
        ctrs = [ctr for ctr in ctrs if ctr in running_containers]
        write_ctrs_to_file(SORTED_CTRS_KEY, ctrs)
    return ctrs


def get_ctrs_from_file(config_key):
    """ Get a list of the containers from disk. """
    path = get_home_prefix(CONFIG[config_key])
    try:
        with open(path, "r") as f:
            ctrs = f.readlines()
            ctrs = [ctr.strip() for ctr in ctrs]
            ctrs = [ctr for ctr in ctrs if len(ctr) > 0]
            return ctrs
    except FileNotFoundError:
        return []


def write_ctrs_to_file(config_key, ctrs):
    path = get_home_prefix(CONFIG[config_key])
    output = ""
    for ctr in ctrs:
        output += f"{ctr}\n"
    output = output[:-1]
    with open(path, "w") as f:
        f.write(output)


def get_unfinished_ctrs():
    ctrs = get_ctrs()
    finished_ctrs = get_ctrs_from_file(FINISHED_CTRS_KEY)
    return [ctr for ctr in ctrs if ctr not in finished_ctrs]


########################################################


def mv_gunzip_errs(tmpfile):
    cmd = get_gunzip_err_cmd(tmpfile)
    res = utils.run_cmd(cmd, output=True).split("\n")
    err_files = []
    for line in res:
        line = line[:-1]  # get rid of the colon (:) at the end
        if len(line) == 0:
            continue
        dst = line.replace(CONFIG[RAW_DIR_KEY], get_home_prefix(CONFIG["MALFORMATTED_DIR"]))
        dst_dir = dst[: dst.rindex("/")]
        mkdir_cmd = f"mkdir -p {dst_dir}"
        utils.run_cmd(mkdir_cmd, output=False, check=False)
        mv_cmd = f"mv {line} {dst_dir}"
        utils.run_cmd(mv_cmd, output=False, check=False)
        LOGGER.debug(f"\t {mv_cmd}")


def unzip_container(ctr):
    pdb.set_trace()

    # get the corresponding paths
    raw_path = get_raw_prefix(ctr)
    dst = get_home_prefix(CONFIG[PROCESS_DIR_KEY])

    # ensure the container has a folder
    mkdir_cmd = f"mkdir -p {dst}"
    utils.run_cmd(mkdir_cmd, output=False, check=False)

    # copy over to the processing folder
    cp_cmd = get_cp_cmd(ctr)
    utils.run_cmd(cp_cmd, output=False, check=False)

    gunzip_cmd = get_gunzip_cmd(dst / ctr)
    with tempfile.NamedTemporaryFile() as tmpfile:
        gunzip_cmd += f" >> {tmpfile.name} 2>&1"
        try:
            LOGGER.debug(f"\t gunzip'ing {ctr}: {gunzip_cmd}")
            utils.run_cmd(gunzip_cmd, output=False, check=True)
        except subprocess.CalledProcessError as e:
            if e.returncode == 2:
                LOGGER.warning(f"\t gunzip warning {ctr}: {e}")
            else:
                LOGGER.error(f"\t gunzip err {ctr}: {e}")
            # pdb.set_trace()
            mv_gunzip_errs(tmpfile.name)


########################################################


def scan():
    """Scans for the next container to process.

    Returns
    -------
    ctr, srvc_files : str, {service : iterator}
    """
    pdb.set_trace()
    process_dir = get_home_prefix(CONFIG[PROCESS_DIR_KEY])

    unfinished = get_unfinished_ctrs()
    ctr = unfinished[0]
    unzip_container(ctr)

    srvc_files = {}
    srvc_globs = CONFIG["GLOBS"]
    ctr_path = process_dir / ctr
    for srvc in srvc_globs:
        file_glob = ctr_path / srvc_globs[srvc]
        srvc_files[srvc] = glob.iglob(str(file_glob))
    return ctr, srvc_files


def cleanup(ctr):
    pdb.set_trace()
    process_dir = get_home_prefix(CONFIG[PROCESS_DIR_KEY])
    ctr_path = process_dir / ctr
    cmd = f"rm -rf {ctr_path}"
    utils.run_cmd(cmd, output=False, check=False)
    LOGGER.debug(f"\t cleaned up {ctr_path}")

    finished_ctrs = get_ctrs_from_file(FINISHED_CTRS_KEY)
    finished_ctrs.append(ctr)
    write_ctrs_to_file(FINISHED_CTRS_KEY, finished_ctrs)


if __name__ == "__main__":
    ctr, srvc_files = scan()
    for srvc in srvc_files:
        for filename in srvc_files[srvc]:
            print(filename)
    cleanup(ctr)