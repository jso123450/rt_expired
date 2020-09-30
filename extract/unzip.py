import logging
import subprocess
from string import Template
import sys
import tempfile

# import pdb

CHUNK_SIZE = 5
LOG_FMT = "%(levelname)s %(asctime)-15s %(message)s"
FIND_TEMP = Template("find /home/ubuntu/data/$ctr/var/log -type f -name '*.gz' | head -n 1")
GUNZIP_TEMP = Template(
    f"gunzip -rf /home/ubuntu/data/$ctr/var/log"
)  # ctr that has not yet been unzipped
FREE_SPACE_CMD = "df -h | grep -w '/dev/vda1' | awk '{print $3}'"
SPACE_THRESHOLD = "25G"
FILES_THRESHOLD = 50_000

logging.basicConfig(filename="/home/ubuntu/unzip.log", format=LOG_FMT, level=logging.DEBUG)
LOGGER = logging.getLogger("unzip")
LOGGER.addHandler(logging.StreamHandler(sys.stdout))


def get_ctrs():
    cmd = "du -sh data/* | sort -h | awk '{print $2}'"
    res = run_cmd(cmd, output=True)
    ctr_paths = res.strip().split("\n")
    return [ctr_path.split("/")[1] for ctr_path in ctr_paths]


def get_find_cmd(ctr):
    return FIND_TEMP.substitute(ctr=ctr)


def get_free_space():
    cmd = FREE_SPACE_CMD
    return run_cmd(cmd, output=True).rstrip()


def get_num_files():
    cmd = 'find data -type f ! -name "*.gz" | wc -l'
    return int(run_cmd(cmd, output=True).rstrip())


def get_next_ctr(ctrs):
    for ctr in ctrs:
        cmd = get_find_cmd(ctr)
        res = run_cmd(cmd, output=True)
        if len(res) > 0:
            return ctr
    return len(ctrs)


def get_gunzip_cmd(ctr):
    return GUNZIP_TEMP.substitute(ctr=ctr)


def get_gunzip_err_cmd(tmpfile):
    return "cat " + tmpfile + " | egrep 'gzip format|unexpected' | awk '{print $2}'"


def mv_gunzip_errs(tmpfile):
    cmd = get_gunzip_err_cmd(tmpfile)
    res = run_cmd(cmd, output=True).split("\n")
    err_files = []
    for line in res:
        line = line[:-1]  # get rid of the colon (:) at the end
        if len(line) == 0:
            continue
        dst = line.replace("/home/ubuntu/data", "/home/ubuntu/malformatted")
        dst_dir = dst[: dst.rindex("/")]
        mkdir_cmd = f"mkdir -p {dst_dir}"
        run_cmd(mkdir_cmd, output=False, check=False)
        mv_cmd = f"mv {line} {dst_dir}"
        run_cmd(mv_cmd, output=False, check=False)
        LOGGER.debug(f"\t {mv_cmd}")


def run_cmd(cmd, output=False, check=False):
    # stdout = sys.stdout if output else subprocess.DEVNULL
    if output:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, check=check)
        return proc.stdout.decode("utf-8")
    else:
        proc = subprocess.run(cmd, shell=True, check=check)
        return None


def should_run(free_space):
    if "G" not in free_space:
        return True
    curr_space = float(free_space[:-1])
    thresh = float(SPACE_THRESHOLD[:-1])
    return curr_space < thresh


def unzip():
    ctrs = get_ctrs()
    LOGGER.debug(f"got ctrs")
    unzipped = 0
    while len(ctrs) > 0 and unzipped < CHUNK_SIZE:
        free_space = get_free_space()
        num_files = get_num_files()
        LOGGER.debug(f"  du: {free_space}")
        LOGGER.debug(f"  num_files: {num_files}")
        if not should_run(free_space) or num_files > FILES_THRESHOLD:
            break
        next_ctr = get_next_ctr(ctrs)
        ctrs = ctrs[ctrs.index(next_ctr) :]
        ctr = ctrs.pop(0)
        unzipped += 1
        LOGGER.debug(f"guzip'ing ctr {ctr}...{CHUNK_SIZE-unzipped} left")
        gunzip_cmd = get_gunzip_cmd(ctr)
        with tempfile.NamedTemporaryFile() as tmpfile:
            gunzip_cmd += f" >> {tmpfile.name} 2>&1"
            try:
                LOGGER.debug(f"\t gunzip'ing {ctr}: {gunzip_cmd}")
                run_cmd(gunzip_cmd, output=False, check=True)
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    LOGGER.warning(f"\t gunzip warning {ctr}: {e}")
                else:
                    LOGGER.error(f"\t gunzip err {ctr}: {e}")
                # pdb.set_trace()
                mv_gunzip_errs(tmpfile.name)

        # break


def main():
    unzip()


if __name__ == "__main__":
    main()
