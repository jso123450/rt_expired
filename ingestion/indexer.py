# stdlib
import pdb

# 3p
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# proj
from log_parser import parser
import utils


########################################################

CONFIG = utils.load_config()["INDEXER"]
LOGGER = utils.get_logger("indexer", f"{CONFIG['HOME_DIR']}/{CONFIG['LOG_PATH']}")
CLIENT = Elasticsearch(hosts=CONFIG["HOSTS"])
MAX_RETRIES = CONFIG["MAX_RETRIES"]


########################################################


def bulk_index(srvc_files):
    # handle errors... probably collect failed operations to retry later
    successes = []
    fails = []
    for srvc in srvc_files:
        for filename in srvc_files[srvc]:
            LOGGER.info(f"{filename}")
            tmp = bulk(CLIENT, parser.parse(filename), max_retries=MAX_RETRIES)
            LOGGER.info(f"  {tmp}")
            break
    return successes, fails
