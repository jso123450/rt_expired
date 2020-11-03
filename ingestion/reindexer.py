# stdlib
import pdb

# 3p
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from elasticsearch_dsl import Search

# proj
from log_parser import parser
import utils


########################################################

CONFIG = utils.load_config()["REINDEXER"]
LOGGER = utils.get_logger("reindexer", f"{CONFIG['HOME_DIR']}/{CONFIG['LOG_PATH']}")
CLIENT = Elasticsearch(hosts=CONFIG["HOSTS"], timeout=30)
MAX_RETRIES = CONFIG["MAX_RETRIES"]

INDICES_UPDATE_MAPPING = {
    "nginx-access-*": True,
    "telnet-*": True,
    # "bad-nginx-access": False,
}
RAW_DIR = "/mnt/nas/vz/root"
CONST_LOG_EVERY_N = 100_000
# WINDOWS = {
#     "START": "2020-08-01",
#     "END": "2020-12-01"
# }
# TIME_FMT = "yyyy-MM-dd"


########################################################


def missing_ip(hit):
    missing = True
    try:
        hit.ip
        missing = False
    except Exception:
        pass
    return missing


def _process_hit(hit):
    # hit.log.container = 718
    # hit.log.path = /var/log...
    filename = f"{RAW_DIR}/{hit.log.container}{hit.log.path}"
    line_number = hit.log.line
    return parser.parse_line(filename, line_number)


def _generator(search, seen_ctrs, is_update=False):
    for idx, hit in enumerate(search.scan()):
        logged = False
        if hit.log.container not in seen_ctrs:
            logged = True
            LOGGER.info(f"  new ctr {hit.log.container} at hit {idx}...")
            seen_ctrs.add(hit.log.container)
        if not logged and idx % CONST_LOG_EVERY_N == 0:
            LOGGER.info(f"  at hit {idx}...")
        if is_update and not missing_ip(hit):
            continue
        doc = _process_hit(hit) # assume not None
        if is_update:
            doc["_id"] = hit.meta.id        # keep id
            doc["_op_type"] = "update"      # mark update
            ## https://stackoverflow.com/questions/35182403/bulk-update-with-pythons-elasticsearch 
            # doc["_source"] = {"doc": doc["_source"]}  
        yield doc


def reindex():
    indices = INDICES_UPDATE_MAPPING
    for idx, idx_ptrn in enumerate(indices):
        LOGGER.info(f"Processing {idx_ptrn}...{len(indices)-idx-1} left")
        s = Search(using=CLIENT, index=idx_ptrn) \
            .params(size=1_000) \
            .sort({"log.container.keyword": {"order": "asc"}})  # sanity-check
            ## we need to reindex all docs, do not filter for time
        LOGGER.info(s.to_dict())
        seen_ctrs = set()
        is_update = indices[idx_ptrn]
        bulk(CLIENT, _generator(s, seen_ctrs, is_update=is_update), max_retries=MAX_RETRIES)
        LOGGER.info(f"Finished {idx_ptrn}...")
