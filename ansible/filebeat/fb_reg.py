import argparse
from datetime import datetime
import json
import logging
import os
import pdb
import tempfile
import subprocess


def _setup_logger() -> logging.Logger:
    """Setup logging."""
    log_format = "[%(asctime)s][%(levelname)s] %(message)s"
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(log_format))
    stream_handler.setLevel(logging.INFO)
    custom_logger = logging.getLogger(__name__)
    custom_logger.addHandler(stream_handler)
    custom_logger.setLevel(logging.INFO)
    custom_logger.propagate = False
    return custom_logger


LOGGER = _setup_logger()


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--registry-file",
        type=str,
        dest="registry_file",
        default="/var/lib/filebeat/registry/filebeat/log.json",
        help="Full path to the Filebeat registry file. "
        'Default: "/var/lib/filebeat/registry/filebeat/log.json"',
    )
    parser.add_argument(
        "--active-dat",
        type=str,
        dest="active_dat",
        default="/var/lib/filebeat/registry/filebeat/active.dat",
        help="Full path to the Filebeat active.dat file. "
        'Default: "/var/lib/filebeat/registry/filebeat/active.dat"',
    )
    parser.add_argument(
        "--unzip",
        dest="unzip",
        action="store_true",
        default=False,
        help="Attempt to unzip logs in filebeat registry.",
    )
    parser.add_argument(
        "--remove",
        dest="remove",
        action="store_true",
        default=False,
        help="Attempt to remove entries in filebeat registry.",
    )
    return parser.parse_args()


def _init_stats():
    return {"count_scrubbed": 0, "count_not_scrubbed": 0, "count_json_err": 0, "count_unzipped": 0}


def _print_summary(args, stats):
    LOGGER.info("Filebeat Registry Scrubber Summary:")
    if args.unzip:
        LOGGER.info("  Registry logs unzipped:         %s", stats["count_unzipped"])
    elif args.remove:
        LOGGER.info("  Registry lines scrubbed:         %s", stats["count_scrubbed"])
        LOGGER.info("  Lines not scrubbed:    %s", stats["count_not_scrubbed"])
        LOGGER.info("  JSON Decode line error:    %s", stats["count_json_err"])


def _read_registry_file(args):
    lines = []
    if args.remove:
        with open(args.registry_file, "r") as f:
            lines = f.readlines()
            lines = [line.rstrip() for line in lines]
            return lines
    with open(args.registry_file, "r") as _registry_file:
        for line in _registry_file:
            obj = json.loads(line)
            if "v" in obj:
                lines.append(obj)
    other_log_file = None
    if os.path.exists(args.active_dat):
        with open(args.active_dat, "r") as _dat_file:
            other_log_file = _dat_file.read()
    try:
        if other_log_file is not None:
            with open(other_log_file, "r") as _registry_file:
                LOGGER.info(f"Opened file in active.dat: {other_log_file}")
                for line in _registry_file:
                    try:
                        obj = json.loads(line[:-1])
                        new_obj = {
                            "v": {
                                "source": obj["source"],
                                "offset": obj["offset"],
                                "type": obj["type"],
                                "timestamp": obj["timestamp"],
                            }
                        }
                        lines.append(new_obj)
                    except json.decoder.JSONDecodeError:
                        pass
    except FileNotFoundError:
        LOGGER.info(f"Could not find file in active.dat: {other_log_file}")
    return lines


def _scrub_registry(stats, lines, tmp):
    idx = 0
    with open(tmp, "a+") as tmp_f:
        while idx < len(lines):
            meta = lines[idx]
            line = lines[idx + 1]
            write = False
            try:
                obj = json.loads(line)
                src = obj["v"]["source"]
                size = os.path.getsize(src)
                write = True
                stats["count_not_scrubbed"] += 1
            except json.decoder.JSONDecodeError:
                # not valid JSON
                write = True
                stats["count_json_err"] += 1
            except KeyError:
                # no ["v"]["source"]
                write = True
            except OSError:
                # do not write this line
                stats["count_scrubbed"] += 1
                pass
            if write:
                tmp_f.write(f"{meta}\n{line}\n")
            idx += 2


def _ensure_correctness(lines, tmp):
    with open(tmp, "r") as tmp_f:
        tmp_lines = tmp_f.readlines()
        tmp_lines = [line.rstrip() for line in tmp_lines]
    idx = 0
    while idx < len(tmp_lines):
        meta = tmp_lines[idx]
        line = tmp_lines[idx + 1]
        meta_idx = lines.index(meta)
        line_idx = lines.index(line)
        assert line_idx == meta_idx + 1
        idx += 2


def _replace_registry(args, tmp):
    suffix = datetime.strftime(datetime.now(), "%m-%d-%Y.%H:%M:%S")
    os.replace(args.registry_file, f"{args.registry_file}.{suffix}")
    os.replace(tmp, args.registry_file)


def _unzip(args, stats):
    registry_data = _read_registry_file(args)
    files = [f"{obj['v']['source']}.gz" for obj in registry_data]
    LOGGER.info(f"{len(files)} to unzip")
    pdb.set_trace()
    for idx, _file in enumerate(files):
        cmd = f"gunzip -f {_file}"
        if idx % 100 == 0:
            LOGGER.info(f"unzipping file {idx} {_file}")
        try:
            subprocess.run(cmd, shell=True, check=True)
            stats["count_unzipped"] += 1
        except subprocess.CalledProcessError as e:
            pass
    _print_summary(args, stats)


def _remove(args, stats):
    try:
        with tempfile.NamedTemporaryFile() as tmp:
            lines = _read_registry_file(args)
            _scrub_registry(stats, lines, tmp.name)
            _ensure_correctness(lines, tmp.name)
            pdb.set_trace()
            _replace_registry(args, tmp.name)
            _print_summary(args, stats)
    except FileNotFoundError:
        # registry replaced
        pass


def main():
    args = _parse_args()
    stats = _init_stats()
    # removing does not work
    #   - gzip all files
    #   - run with unzip option
    # if args.remove:
    #     _remove(args, stats)
    if args.unzip:
        _unzip(args, stats)


if __name__ == "__main__":
    main()
