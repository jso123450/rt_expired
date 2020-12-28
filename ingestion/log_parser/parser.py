# stdlib
import sys, gzip, json
import os
import re
from datetime import datetime
import dateutil.parser
import concurrent.futures as cfutures
from pathlib import Path
import pdb

# proj
from enum_types import LogType
from log_parser.grokpatterns import (
    TELNET_MATCHER,
    NGINX_ACCESS_MATCHER,
    NGINX_ERROR_MATCHER,
    FTP_MATCHER,
    POSTFIX_PREFIX_MATCHER,
    POSTFIX_MESSAGE_MATCHER,
)
import utils

# constants
CONFIG = utils.load_config()
LOGGER = utils.get_logger("parser")

RAW_DIR = CONFIG["SCANNER"]["RAW_DIR"]
TIME_FMT = CONFIG["TIME"]["FMT"]
TIME_START = datetime.strptime(CONFIG["TIME"]["START"], TIME_FMT).timestamp()
TIME_END = datetime.strptime(CONFIG["TIME"]["END"], TIME_FMT).timestamp()
TIMEOUT_DOC_PARSE = 30
WORKERS = 4
CHUNK_SIZE = 10_000

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
    ctid_path = fname[len(RAW_DIR) + 1 :]
    parts = ctid_path.split("/")
    ctid = parts[0]
    path = "/" + "/".join(parts[1:])
    common = {"_source": {"log": {"container": ctid, "path": path, "line": line}}}
    return common


def _parse_ftp(common, string):
    entry = common
    for matcher in FTP_MATCHER:
        match = matcher.match(string.decode())
        if match != None:
            ftp = match
            timestamp = datetime.strptime(ftp["timestamp"], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            ip = ftp["ip"]
            del ftp["timestamp"]
            del ftp["ip"]
            entry["_index"] = "ftp-{}".format(timestamp[:7].replace("-", "."))
            entry["_source"].update({"ftp": ftp, "ip": ip, "@timestamp": timestamp})
            return entry

    entry["_index"] = "bad-ftp"
    entry["_source"]["message"] = string.decode()
    return entry


def _parse_ssh(common, string):
    entry = common
    try:
        ssh = json.loads(string)
        timestamp = ssh["timestamp"]
        ssh["ip"] = ssh["src_ip"]
        del ssh["src_ip"]
        del ssh["timestamp"]
        entry["_index"] = "ssh-{}".format(timestamp[:7].replace("-", "."))
        entry["_source"].update({"ssh": ssh, "@timestamp": timestamp})
    except:
        entry["_index"] = "bad-ssh"
        entry["_source"]["message"] = str(string)

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
    entry["_index"] = "telnet-" + grok["timestamp"][0:4] + "." + grok["timestamp"][5:7]
    entry["_source"]["@timestamp"] = (
        datetime.strptime(grok["timestamp"], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
    )
    entry["_source"]["ip"] = grok["ip"]  # should always be here
    entry["_source"]["telnet"] = {"user": grok["user"], "password": grok["password"]}
    return entry


def _create_nginx_access_entry(common, string):
    entry = common
    grok = None
    matchers = NGINX_ACCESS_MATCHER
    for idx, matcher in enumerate(matchers):
        grok = matcher.match(string.decode())
        if grok is not None and (
            "request" in grok or ("method" in grok and grok["method"] in HTTP_METHODS)
        ):
            break

    if grok is None:
        entry["_index"] = "bad-2-nginx-access"
        entry["_source"]["message"] = string.decode()
        return entry

    timestamp = utils.get_nginx_timestamp(grok["timestamp"])

    if "request" not in grok and ("method" in grok and grok["method"] not in HTTP_METHODS):
        entry["_index"] = "bad-2-nginx-access"
        entry["_source"]["message"] = string.decode()
        entry["_source"]["@timestamp"] = timestamp
        return entry

    entry["_source"]["@timestamp"] = timestamp
    entry["_index"] = f"nginx-access-{timestamp[0:4]}.{timestamp[5:7]}"
    entry["_source"]["ip"] = grok["remote_ip"]  # should always be here
    if "unknown_message_pattern" in grok:
        entry["_source"]["nginx"] = {"unknown_message": string.decode()}
    else:
        entry["_source"]["nginx"] = {
            "method": grok.get("method", ""),
            "user_name": grok.get("user_name", ""),
            "path": grok.get("url", ""),
            "response_code": grok.get("response_code", ""),
            "response_size": grok.get("bytes", ""),
            "referrer": grok.get("referrer", ""),
            "user_agent": grok.get("agent", ""),
            "http_version": grok.get("http_version", ""),
            "http_string": grok.get("http_string", ""),
            # fields for logs with pipes
            "scheme": grok.get("scheme", ""),
            "http_host": grok.get("http_host", ""),
            "http_accept_charset": grok.get("http_accept_charset", ""),
            "http_accept_encoding": grok.get("http_accept_encoding", ""),
            "http_accept_language": grok.get("http_accept_language", ""),
            "http_content_length": grok.get("http_content_length", ""),
            "http_content_md5": grok.get("http_content_md5", ""),
            "http_cookie": grok.get("http_cookie", ""),
            "http_from": grok.get("http_from", ""),
            "http_x_forwarded_for": grok.get("http_x_forwarded_for", ""),
            "http_x_forwarded_host": grok.get("http_x_forwarded_host", ""),
            "http_x_wap_profile": grok.get("http_x_wap_profile", ""),
            "http_x_request_id": grok.get("http_x_request_id", ""),
            "http_x_correlation_id": grok.get("http_x_correlation_id", ""),
            "host": grok.get("host", ""),
            "request": grok.get("request", ""),
            "gzip_ratio": grok.get("gzip_ratio", ""),
        }

    return entry


def _create_nginx_error_entry(common, string):
    entry = common
    grok = None
    matchers = NGINX_ERROR_MATCHER
    for idx, matcher in enumerate(matchers):
        try:
            grok = matcher.match(string.decode())
        except UnicodeDecodeError:
            break
        if grok is not None:
            break

    if grok is None:
        entry["_index"] = "bad-nginx-error"
        try:
            entry["_source"]["message"] = string.decode()
        except UnicodeDecodeError:
            entry["_source"]["message"] = str(string)
        return entry

    timestamp = datetime.strptime(grok["timestamp"], "%Y/%m/%d %H:%M:%S").isoformat() + "Z"

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
    match = POSTFIX_PREFIX_MATCHER.match(string.decode())
    if match != None and match["program"] in POSTFIX_MESSAGE_MATCHER:
        matches = []
        for matcher in POSTFIX_MESSAGE_MATCHER[match["program"]]:
            parsed_msg = matcher.grok(match["message"])
            if (
                parsed_msg != None
                and "postfix_client_hostname" in parsed_msg
                and "postfix_client_ip" in parsed_msg
                and "postfix_client_port" in parsed_msg
                and parsed_msg["postfix_client_hostname"] == None
                and parsed_msg["postfix_client_ip"] == None
                and parsed_msg["postfix_client_port"] == None
            ):
                del parsed_msg["postfix_client_hostname"]
                del parsed_msg["postfix_client_ip"]
                del parsed_msg["postfix_client_port"]
            if parsed_msg:
                matches.append(
                    (
                        parsed_msg,
                        sum([1 for key in parsed_msg if [parsed_msg[key] == None]]),
                        len(parsed_msg.keys()),
                    )
                )
        if len(matches):
            parsed_msg = sorted(matches, key=lambda x: (x[1], x[2]))[0][0]
            timestamp = datetime.strptime(match["timestamp"], "%b  %d %H:%M:%S")
            if timestamp.month <= 7:
                timestamp.replace(year=2020)
            else:
                timestamp.replace(year=2019)
            entry["_index"] = "{}-{}.{}".format(
                match["program"].replace("/", "-"), timestamp.year, timestamp.month
            )
            # entry["_type"] = match['program'].replace('/', '_')
            entry["_source"]["message"] = match["message"]
            entry["_source"]["program"] = match["program"]
            entry["_source"]["@timestamp"] = match["timestamp"]
            for key in parsed_msg:
                entry["_source"][key] = parsed_msg[key]
            return entry
        entry["_index"] = "bad-2-{}".format(match["program"].replace("/", "-"))
    else:
        entry["_index"] = "bad-2-postfix"
    timestamp = datetime.strptime(match["timestamp"], "%b  %d %H:%M:%S")
    if timestamp.month <= 7:
        timestamp = timestamp.replace(year=2020)
    else:
        timestamp = timestamp.replace(year=2019)
    entry["_source"]["@timestamp"] = timestamp.isoformat() + "Z"
    entry["_source"]["message"] = string.decode()
    return entry


########################################################

LOG_TYPE_PARSER = {
    LogType.NGINX: _parse_nginx,
    LogType.TELNET: _parse_telnet,
    LogType.FTP: _parse_ftp,
    LogType.SSH: _parse_ssh,
    LogType.SMTP: _parse_smtp,
}


def get_nth_line(n, fp):
    for idx, line in enumerate(fp):
        if idx == n:
            return line


def parse_line(filename, line_num):
    """Parses a specific line number in the filename. The line number is 0-indexed."""
    # don't use linecache since it loads entire file in memory
    log_type = LogType.get_type(filename)
    with gzip.open(filename, "rb") as f:
        try:
            for idx, line in enumerate(f):
                if idx != line_num:
                    continue
                without_newline = line[:-1]
                common = _parse_common(filename, idx)
                doc = parse_line_timeout(log_type, common, filename, without_newline)
                return doc
        except Exception as e:
            LOGGER.warning(f"{e}: {filename} - line {line_num}")


def parse_line_timeout(log_type, common, filename, without_newline):
    def _get_future(_exec, log_type, common, filename, without_newline):
        func = LOG_TYPE_PARSER[log_type]
        if log_type == LogType.NGINX:
            return _exec.submit(func, common, filename, without_newline)
        else:
            return _exec.submit(func, common, without_newline)

    def terminate_thread(thread):
        """Terminates a python thread from another thread.

        :param thread: a threading.Thread instance
        """
        if not thread.isAlive():
            return

        from ctypes import py_object, pythonapi, c_long

        exc = py_object(SystemExit)
        res = pythonapi.PyThreadState_SetAsyncExc(c_long(thread.ident), exc)
        if res == 0:
            raise ValueError("nonexistent thread id")
        elif res > 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    executor = cfutures.ThreadPoolExecutor(max_workers=1)
    future = _get_future(executor, log_type, common, filename, without_newline)
    doc = None
    kill = False
    try:
        doc = future.result(timeout=TIMEOUT_DOC_PARSE)
    except cfutures.TimeoutError:
        kill = True
    executor.shutdown(wait=False)
    if kill:
        for t in executor._threads:
            try:
                terminate_thread(t)
            except ValueError:
                pass
            except SystemError:
                LOGGER.error(f"could not kill thread in {filename}:{line_num}")
    return doc


def doc_in_time_window(doc):
    doc_time = dateutil.parser.isoparse(doc["_source"]["@timestamp"]).timestamp()
    return doc_time >= TIME_START and doc_time <= TIME_END


def file_in_time_window(filename):
    _file_path = Path(filename)
    _file_str = str(filename)
    try:
        maybe_time = _file_path.name.split(".")[-2]
        if "cowrie" in _file_str:  # looks like 2019-10-02
            fmt = "%Y-%m-%d"
        else:  # looks like 20190912-1568266698
            maybe_time = maybe_time.split("-")[0]
            fmt = "%Y%m%d"
        _file_time = datetime.strptime(maybe_time, fmt).timestamp()
        return _file_time >= TIME_START  # time is the time it was rotated
    except Exception as e:
        LOGGER.debug(f"   no time in filename {filename}")
    return True


def get_num_lines(filename):
    with gzip.open(filename) as f:
        for idx, line in enumerate(f):
            pass
    return idx + 1


# def get_n_chunks(n, maximum):
#     chunks = []
#     for i in range(n):
#         start = round(i * (maximum / n))
#         end = round((i + 1) * (maximum / n))
#         chunks.append((start, end))
#     return chunks


def get_chunks(_list, n):
    for i in range(0, len(_list), n):
        yield (i, i + n)


def parse_chunk(filename, chunk):
    def _get_future(_exec, log_type, common, filename, without_newline):
        func = LOG_TYPE_PARSER[log_type]
        if log_type == LogType.NGINX:
            return _exec.submit(func, common, filename, without_newline)
        else:
            return _exec.submit(func, common, without_newline)

    def terminate_thread(thread):
        """Terminates a python thread from another thread.

        :param thread: a threading.Thread instance
        """
        if not thread.isAlive():
            return

        from ctypes import py_object, pythonapi, c_long

        exc = py_object(SystemExit)
        res = pythonapi.PyThreadState_SetAsyncExc(c_long(thread.ident), exc)
        if res == 0:
            raise ValueError("nonexistent thread id")
        elif res > 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    log_type = LogType.get_type(filename)
    start, end = chunk
    parsed_lines = 0
    executor = cfutures.ThreadPoolExecutor(max_workers=WORKERS)
    futures = []
    with gzip.open(filename, "rb") as f:
        for idx, line in enumerate(f):
            if idx < start or idx >= end:
                continue
            without_newline = line.strip()
            common = _parse_common(filename, idx)
            future = _get_future(executor, log_type, common, filename, without_newline)
            futures.append(future)
    kill = False
    for idx, future in enumerate(futures):
        try:
            doc = future.result(timeout=TIMEOUT_DOC_PARSE)
            if doc is not None and doc_in_time_window(doc):
                parsed_lines += 1
                yield doc
        except cfutures.TimeoutError:
            LOGGER.warning(f"     line {idx+start} timed out")
            kill = True
    executor.shutdown(wait=False)
    if kill:
        for t in executor._threads:
            try:
                terminate_thread(t)
            except ValueError:
                pass
            except SystemError:
                LOGGER.error(f"could not kill thread {t.ident} while parsing {filename}:{chunk}")


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
    if not file_in_time_window(filename):
        return
    LOGGER.debug(f"   parsing {filename}")
    total_lines = get_num_lines(filename)
    _list = range(total_lines)
    chunks = get_chunks(_list, CHUNK_SIZE)
    parsed_lines = 0
    for idx, chunk in enumerate(chunks):
        LOGGER.debug(f"    chunk {idx} [{chunk[0]}, {chunk[1]}) from {filename}")
        for doc in parse_chunk(filename, chunk):
            parsed_lines += 1
            yield doc
    LOGGER.debug(f"   parsed {parsed_lines} docs in time window from {filename}")


# def parse(filename):
#     """Parses a log file and returns a generator that yields the parsed documents.
#     These documents should be ready to index into Elasticsearch.

#     Parameters
#     ----------
#     filename : str or Path

#     Returns
#     -------
#     doc_generator : generator
#         generator that yields documents for es.bulk
#         {
#             '_index': '{service}-YYYY-MM',
#             '_source': {
#                 "title": "Hello World!",
#                 "body": "..."
#             }
#         }
#     """
#     log_type = LogType.get_type(filename)
#     parsed_lines = 0
#     if not file_in_time_window(filename):
#         # LOGGER.debug(f"   not in time window {filename}")
#         pass
#     else:
#         LOGGER.debug(f"   parsing {filename}")
#         with gzip.open(filename, "rb") as f:
#             try:
#                 for idx, line in enumerate(f):
#                     if idx % 100_000 == 0:
#                         LOGGER.debug(f"    line {idx} on {filename}")
#                     try:
#                         without_newline = line[:-1]
#                         common = _parse_common(filename, idx)
#                         doc = parse_line_timeout(log_type, common, filename, without_newline)
#                         if doc is not None and doc_in_time_window(doc):
#                             parsed_lines += 1
#                             # pdb.set_trace()
#                             yield doc
#                     except Exception as e:
#                         print(e)
#                         LOGGER.warning(f"{e}: {line}")
#             except OSError as e:
#                 LOGGER.warning(f"  {e}: {filename}")
#         LOGGER.debug(f"   parsed {parsed_lines} docs in time window from {filename}")
