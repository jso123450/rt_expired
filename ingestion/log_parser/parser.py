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
                                POSTFIX_PREFIX_MATCHER, \
                                POSTFIX_MESSAGE_MATCHER
import utils

# constants
CONFIG = utils.load_config()
RAW_DIR = CONFIG["SCANNER"]["RAW_DIR"]
LOGGER = utils.get_logger("parser", f"{CONFIG['PARSER']['HOME_DIR']}/{CONFIG['PARSER']['LOG_PATH']}")

HTTP_METHODS = {
    "GET", 
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
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
    entry = common
    for matcher in FTP_MATCHER:
        match = matcher.match(string.decode())
        if match != None:
            ftp = match
            timestamp = datetime.strptime(ftp['timestamp'], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            ip = ftp['ip']
            del(ftp['timestamp'])
            del(ftp['ip'])
            entry["_index"] = "ftp-{}".format(timestamp[:7].replace("-", "."))
            entry["_source"].update({"ftp": ftp, "ip": ip, "@timestamp": timestamp})
            return entry
    
    entry["_index"] = "bad-ftp"
    entry["_source"]["message"] = string.decode()
    return entry

def _parse_ssh(common, string):
    entry = common
    ssh = json.loads(string)
    timestamp = ssh["timestamp"]
    ssh["ip"] = ssh["src_ip"]
    del(ssh["src_ip"])
    del(ssh["timestamp"])
    entry["_index"] = "ssh-{}".format(timestamp[:7].replace("-", "."))
    entry["_source"].update({"ssh": ssh, "@timestamp": timestamp})
    return entry

def _parse_telnet(common, string):
    entry = common
    grok = None
    for matcher in TELNET_MATCHER:
        grok = matcher.match(string.decode())
        if grok is not None:
            break
    if grok is None:
        entry["_index"] = "bad-telnet"
        entry["_source"]["message"] = string.decode()
        return entry
    # pdb.set_trace()
    entry["_index"] = "telnet-" + grok['timestamp'][0:4] + "." + grok['timestamp'][5:7]
    entry["_source"]["@timestamp"] = datetime.strptime(grok['timestamp'], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
    entry["_source"]["telnet"] = { "user": grok['user'], "password": grok['password'] }
    return entry


def _create_nginx_access_entry(common, string):
    entry = common
    grok = None
    matchers = NGINX_ACCESS_MATCHER
    for idx, matcher in enumerate(matchers):
        grok = matcher.match(string.decode())
        if grok is not None and ("method" in grok and grok["method"] in HTTP_METHODS):
            break

    if grok is None:
        entry["_index"] = "bad-nginx-access"
        entry["_source"]["message"] = string.decode()
        return entry
    
    timestamp = utils.get_nginx_timestamp(grok["timestamp"]) 

    if "unknown_message_pattern" in grok or ("method" in grok and grok["method"] not in HTTP_METHODS):
        entry["_index"] = "bad-nginx"
        entry["_source"]["message"] = string.decode()
        entry["_source"]["@timestamp"] = timestamp
        return entry
    
    entry["_source"]["@timestamp"] = timestamp
    entry["_index"] = f"nginx-access-{timestamp[0:4]}.{timestamp[5:7]}"
    entry["_source"]["nginx"] = {
        "method": grok.get("method", ""),
        "user_name": grok["user_name"],
        "path": grok.get("url", ""),
        "response_code": grok["response_code"],
        "response_size": grok["bytes"],
        "referrer": grok["referrer"],
        "user_agent": grok["agent"],
        "http_version": grok.get("http_version", ""),
        "http_string": grok.get("http_string", "")
    }
    return entry

def _create_nginx_error_entry(common, string):
    LOGGER.info(f"nginx error")
    entry = common
    grok = None
    matchers = NGINX_ERROR_MATCHER
    for idx, matcher in enumerate(matchers):
        grok = matcher.match(string.decode())
        if grok is not None:
            break
    
    if grok is None:
        entry["_index"] = "bad-nginx-error"
        entry["_source"]["message"] = string.decode()
        return entry

    timestamp = datetime.strptime(grok['timestamp'], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
    
    entry["_source"]["@timestamp"] = timestamp
    entry["_index"] = f"nginx-error-{timestamp[0:4]}.{timestamp[5:7]}"
    entry["_source"]["error"] = {
        "level": grok["level"],
        "pid": grok["pid"],
        "tid": grok["tid"],
        "connection_id": grok["connection_id"],
        "message": grok["message"],
    }
    return entry

def _parse_nginx_access(common, string):
    return _create_nginx_access_entry(common, string)


def _parse_nginx_error(common, string):
    return _create_nginx_error_entry(common, string)

def _parse_nginx(common, filename, string):
    if "access" in filename:
        return _parse_nginx_access(common, string)
    else:
        return _parse_nginx_error(common, string)

def _parse_smtp(common, string):
    entry = common
    match = prefix_matcher.match(string)
    if match != None and match['program'] in message_matcher:
        for matcher in message_matcher[match['program']]:
            parsed_msg = matcher.grok(match['message'])
            if parsed_msg:
                for key in parsed_msg:
                    if parsed_msg[key] == None:
                        break
                else:
                    timestamp = datetime.strptime(match['timestamp'], '%b  %d %H:%M:%S')
                    timestamp.year = 2019
                    entry["_index"] = "{}-{}.{}".format(match['program'].replace('/', '-'), 
                        timestamp.year, timestamp.month)
                    entry["_source"]["message"] = match['message']
                    entry["_source"]["program"] = match['program']
                    entry["_source"]["_type"] = match['program'].replace('/', '_')
                    entry["_source"]["@timestamp"] = match['timestamp']
                    for key in parsed_msg:
                        entry["_source"][key] = parsed_msg[key]
                    return entry
    return None

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