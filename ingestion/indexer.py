# 3p
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# proj
import parser
import utils


########################################################

CONFIG = utils.load_config()["INDEXER"]
LOGGER = utils.get_logger("indexer", f"{CONFIG['HOME_DIR']}/{CONFIG['LOG_PATH']}")
CLIENT = Elasticsearch(hosts=CONFIG["HOSTS"])
MAX_RETRIES = CONFIG["MAX_RETRIES"]


########################################################


def bulk_index(srvc_files):
    # handle errors... probably collect failed operations to retry later
    success = True
    for srvc in srvc_files:
        for filename in srvc_files[srvc]:
            bulk(CLIENT, parser.parse(filename), max_retries=MAX_RETRIES)
    return success
