# stdlib
import sys, gzip, json
import os
import re
from datetime import datetime
import pdb

# proj
from enum_types import LogType
from log_parser.grokpatterns import TELNET_MATCHER, \
                                NGINX_ACCESS_MATCHER, \
                                NGINX_ERROR_MATCHER, \
                                FTP_MATCHER, \
                                POSTFIX_MATCHER
import utils

# constants
CONFIG = utils.load_config()
RAW_DIR = CONFIG["SCANNER"]["RAW_DIR"]
LOGGER = utils.get_logger("parser", f"{CONFIG['PARSER']['HOME_DIR']}/{CONFIG['PARSER']['LOG_PATH']}")

HTTP_METHODS = {
    "GET", 
    "POST",
    "PROPFIND",
}



########################################################

def _parse_common(fname, line):
    ctid_path = fname[len(RAW_DIR)+1:]
    parts = ctid_path.split("/")
    ctid = parts[0]
    path = "/" + "/".join(parts[1:])
    common = {
        "_source": {
            "log": {
                "container": ctid,
                "path": path,
                "line": line
            }
        }
    }
    return common


def _parse_ftp(common, string):
    for matcher in FTP_MATCHER:
        match = matcher.match(string.decode())
        if match != None:
            ftp = match
            timestamp = ftp['timestamp']
            ip = ftp['ip']
            del(ftp['timestamp'])
            del(ftp['ip'])
            doc = {
                "_index": "ftp-{}".format(timestamp[:7].replace("-", ".")),
                "_type": "ftp",
                "_source": {
                    "ftp": ftp,
                    "ip": ip,
                    "@timestamp": timestamp
                },
            }
            doc.update(common)
            return doc
    return None

def _parse_ssh(common, string):
    ssh = json.loads(string)
    ssh["ip"] = ssh["src_ip"]
    ssh["@timestamp"] = ssh["timestamp"]
    del(ssh["src_ip"])
    del(ssh["timestamp"])
    doc = {
        "_index": "ssh-{}".format(ssh['@timestamp'][:7].replace("-", ".")),
        "_type": "ssh",
        "_source": ssh
    }
    doc.update(common)
    return doc


# def _parsepostfix(string):
#     for matcher in POSTFIX_MATCHER:
#         match = matcher.match(string.decode())
#         print(match)
#         if match != None:
#             print(match)

def _parse_telnet(common, string):
    entry = common
    grok = None
    for matcher in TELNET_MATCHER:
        grok = matcher.match(string.decode())
        if grok is not None:
            break
    if grok is None:
        return None
    # pdb.set_trace()
    entry["_source"]["@timestamp"] = datetime.strptime(grok['timestamp'], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
    entry["_source"]["_index"] = "telnet-" + grok['timestamp'][0:4] + "." + grok['timestamp'][5:7]
    entry["_source"]["_type"] = "ftp"
    entry["_source"]["ftp"] = { "user": grok['user'], "password": grok['password'] }
    return entry


def _create_nginx_entry(common, string, type):
    entry = common
    grok = None
    matchers = NGINX_ACCESS_MATCHER
    if type == "error":
        matchers = NGINX_ERROR_MATCHER
    for idx, matcher in enumerate(matchers):
        grok = matcher.match(string.decode())
        if grok is not None and ("method" in grok and grok["method"] in HTTP_METHODS):
            break
    if grok is None:
        return None
    timestamp = datetime.strptime(grok['timestamp'], "%d/%b/%Y:%H:%M:%S %z").isoformat() + "Z"
    entry["_source"]["@timestamp"] = timestamp
    entry["_index"] = f"nginx-{type}-{timestamp[0:4]}.{timestamp[5:7]}"
    entry["_type"] = f"nginx-{type}"

    if type == "access":
        entry["_source"]["nginx"] = {
            "method": grok.get("method", ""),
            "user_name": grok["user_name"],
            "path": grok.get("url", ""),
            "response_code": grok["response_code"],
            "response_size": grok["bytes"],
            "referrer": grok["referrer"],
            "user_agent": grok["agent"],
            "http_string": grok.get("http_string", "")
        }
    else: 
        entry["_source"]["error"] = {
            "level": grok["level"],
            "pid": grok["pid"],
            "tid": grok["tid"],
            "connection_id": grok["connection_id"],
            "message": grok["message"],
        }
    return entry



def _parse_nginx_access(common, string):
    return _create_nginx_entry(common, string, "access")


def _parse_nginx_error(common, string):
    return _create_nginx_entry(common, string, "error")

def _parse_nginx(common, filename, string):
    if "access" in filename:
        return _parse_nginx_access(common, string)
    else:
        return _parse_nginx_error(common, string)

########################################################

LOG_TYPE_PARSER = {
    LogType.NGINX: _parse_nginx,
    LogType.TELNET: _parse_telnet,
    LogType.FTP: _parse_ftp,
    LogType.SSH: _parse_ssh,
    # LogType.SMTP: _parse_smtp,
}


def parse(filename):
    """Parses a log file and returns a generator that yields the parsed documents.
    These documents should be ready to index into Elasticsearch.

    Parameters
    ----------
    filename : str or Path

    Returns
    -------
    doc_generator : generator
        generator that yields documents for es.bulk
        {
            '_index': '{service}-YYYY-MM',
            '_source': {
                "title": "Hello World!",
                "body": "..."
            }
        }
    """
    log_type = LogType.get_type(filename)
    with gzip.open(filename, "rb") as f:
        try:
            for idx, line in enumerate(f):
                without_newline = line[:-1]
                common = _parse_common(filename, idx)
                doc = None
                if log_type == LogType.NGINX:
                    doc = LOG_TYPE_PARSER[log_type](common, filename, without_newline)
                else:
                    doc = LOG_TYPE_PARSER[log_type](common, without_newline)
                if doc is not None:
                    # pdb.set_trace()
                    yield doc
        except OSError as e:
            LOGGER.warning(f"  {e}: {filename}")