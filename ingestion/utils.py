import csv
from datetime import datetime
import json
import logging
import logging.config
from pathlib import Path
import subprocess
import sys


################################################################################


BASE_DIR = Path("/home/ubuntu/rt_expired")
CONFIG_FILE = BASE_DIR / "ingestion/config.json"
CONTAINERS_FILE = BASE_DIR / "data/containers.txt"
PLACEBOS_FILE = BASE_DIR / "data/placebos.txt"
LOG_FMT = "%(name)s %(levelname)s %(asctime)-15s %(message)s"
CONFIG = None


################################################################################


class _ExcludeErrorsFilter(logging.Filter):
    def filter(self, record):
        """Filters out log messages with log level ERROR (numeric value: 40) or higher."""
        return record.levelno < logging.ERROR


def load_config():
    global CONFIG
    if CONFIG is None:
        with open(CONFIG_FILE) as f:
            CONFIG = json.load(f)
            configure_loggers()
    return CONFIG


def configure_loggers():
    config = {
        "version": 1,
        "filters": {"exclude_errors": {"()": _ExcludeErrorsFilter}},
        "formatters": {
            # Modify log message format here or replace with your custom formatter class
            "file_formatter": {"format": CONFIG["LOG"]["FMT"]},
            "stdout_formatter": {"format": CONFIG["LOG"]["FMT"]},
        },
        "handlers": {
            "console_stderr": {
                # Sends log messages with log level ERROR or higher to stderr
                "class": "logging.StreamHandler",
                "level": "ERROR",
                "formatter": "stdout_formatter",
                "stream": sys.stderr,
            },
            "console_stdout": {
                # Sends log messages with INFO <= log level to stdout
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "stdout_formatter",
                "filters": ["exclude_errors"],
                "stream": sys.stdout,
            },
            "file": {
                # Sends all log messages to a file
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "formatter": "file_formatter",
                "filename": "./logs/log.log",
                "encoding": "utf8",
            },
            # "file_indexer": {
            #     # Sends all log messages to a file
            #     "class": "logging.FileHandler",
            #     "level": "DEBUG",
            #     "formatter": "file_formatter",
            #     "filename": f"{CONFIG['INDEXER']}/{CONFIG['INDEXER']['LOG_PATH']}",
            #     "encoding": "utf8",
            # },
            # "file_reindexer": {
            #     # Sends all log messages to a file
            #     "class": "logging.FileHandler",
            #     "level": "DEBUG",
            #     "formatter": "file_formatter",
            #     "filename": f"{CONFIG['REINDEXER']}/{CONFIG['REINDEXER']['LOG_PATH']}",
            #     "encoding": "utf8",
            # },
            # "file_scanner": {
            #     # Sends all log messages to a file
            #     "class": "logging.FileHandler",
            #     "level": "DEBUG",
            #     "formatter": "file_formatter",
            #     "filename": f"{CONFIG['SCANNER']}/{CONFIG['SCANNER']['LOG_PATH']}",
            #     "encoding": "utf8",
            # },
            # "file_parser": {
            #     # Sends all log messages to a file
            #     "class": "logging.FileHandler",
            #     "level": "DEBUG",
            #     "formatter": "file_formatter",
            #     "filename": f"{CONFIG['PARSER']}/{CONFIG['PARSER']['LOG_PATH']}",
            #     "encoding": "utf8",
            # },
        },
        "root": {
            # In general, this should be kept at 'NOTSET'.
            # Otherwise it would interfere with the log levels set for each handler.
            "level": "NOTSET",
            "handlers": ["console_stderr", "console_stdout", "file"],
        },
        "loggers": {
            "scanner": {},
            "parser": {},
            "indexer": {},
            "reindexer": {},
        },
    }
    logging.config.dictConfig(config)


def get_logger(name):
    if CONFIG is None:
        load_config()
    return logging.getLogger(name)


def _get_containers(_file):
    ctids = {}
    with open(_file) as f:
        for idx, line in enumerate(f):
            if idx == 0:
                continue
            ctid, ip, domain = line.rstrip().split(" ")
            ctids[ctid] = {"ip": ip, "domain": domain}
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


def run_cmd(cmd, output=False, check=False):
    if output:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, check=check)
        return proc.stdout.decode("utf-8")
    else:
        proc = subprocess.run(cmd, shell=True, check=check)
        return None


def get_nginx_timestamp(timestamp):
    try:
        return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z").isoformat()  # has timezone
    except ValueError:
        return (
            datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S").isoformat() + "Z"
        )  # no timezone (assume UTC)


def get_pipe_headers(grok):
    pipe_header = ""
    if "pipe_header" in grok and grok["pipe_header"] is not None:
        pipe_header += grok["pipe_header"]
    if "pipe_header_2" in grok and grok["pipe_header_2"] is not None:
        pipe_header += grok["pipe_header_2"]
    return pipe_header