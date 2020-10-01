from collections import defaultdict
import json
import logging
from pathlib import Path
import pdb
import sys

sys.path.append("../extract")

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, A
from elasticsearch_dsl.connections import connections

import utils

PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
INDICES_MAPPING = {
    "nginx-access-*": "nginx.access.remote_ip.keyword",
    # "postfix-qmgr-*": "postfix-qmgr",
    "postfix-smtpd-*": "postfix_client_ip.keyword",
    "telnet-*": "telnet.ip.keyword",
    "ftp-*": "ftp.ip.keyword",
}
BOT_IPS = Path("../data/bots.json")
LOGGER = utils.get_logger(__name__, logging.INFO)
CHECK_AGAIN = False


def init_ctr_logs():
    ctr_logs = defaultdict(lambda: defaultdict(list))
    try:
        with open(BOT_IPS, "r") as f:
            loaded = json.loads(f.read())
        for ctr in loaded:  # keep it the defaultdict(...)
            for idx_ptrn in loaded[ctr]:
                ctr_logs[ctr][idx_ptrn] = loaded[ctr][idx_ptrn]
    except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
        pass
    return ctr_logs


def write_ctr_logs(ctr_logs):
    with open(BOT_IPS, "w+") as f:
        json.dump(ctr_logs, f)


# def get_body(ctr, idx_ptrn, after_key=None):
#     field = INDICES_MAPPING[idx_ptrn]
#     body = {
#         "size": 0,
#         "query": {"term": {"container.id": str(ctr)}},
#         "aggs": {
#             "by_ip": {
#                 "composite": {"size": 10_000, "sources": [{"ip": {"terms": {"field": field}}}]}
#             }
#         },
#     }
#     if after_key is not None:
#         body["aggs"]["by_ip"]["composite"]["after"] = after_key
#     return body


def scan_aggs(search, source_aggs, inner_aggs={}, size=10):
    """
    Helper function used to iterate over all possible bucket combinations of
    ``source_aggs``, returning results of ``inner_aggs`` for each. Uses the
    ``composite`` aggregation under the hood to perform this.
    """

    def run_search(**kwargs):
        s = search[:0]
        s.aggs.bucket("comp", "composite", sources=source_aggs, size=size, **kwargs)
        for agg_name, agg in inner_aggs.items():
            s.aggs["comp"][agg_name] = agg
        return s.execute()

    response = run_search()
    while response.aggregations.comp.buckets:
        for b in response.aggregations.comp.buckets:
            yield b
        if "after_key" in response.aggregations.comp:
            after = response.aggregations.comp.after_key
        else:
            after = response.aggregations.comp.buckets[-1].key
        response = run_search(after=after)


connections.configure(default={"hosts": ["130.245.169.240:9200"]})
# pdb.set_trace()
ctr_logs = init_ctr_logs()

for idx, ctr in enumerate(PLACEBOS):
    LOGGER.info(f"Processing {ctr} {PLACEBOS[ctr]}...{len(PLACEBOS)-idx-1} left")
    found_results = False
    ctr = str(ctr)  # json saves int keys as str
    for idx_ptrn in INDICES_MAPPING:
        if not CHECK_AGAIN and idx_ptrn in ctr_logs[ctr]:
            continue
        s = Search(index=idx_ptrn).query("term", **{"container.id.keyword": str(ctr)})
        source_agg = {"ip": A("terms", field=INDICES_MAPPING[idx_ptrn])}
        ips = [b.key.ip for b in scan_aggs(s, source_agg, size=10_000)]
        ctr_logs[ctr][idx_ptrn] = ips
        found_results = found_results or len(ips) > 0
        LOGGER.info(f"    {idx_ptrn}: {len(ctr_logs[ctr][idx_ptrn])}")
    LOGGER.info(f"  found_results={found_results}")
    if found_results:
        write_ctr_logs(ctr_logs)