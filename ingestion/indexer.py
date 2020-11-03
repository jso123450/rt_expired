# stdlib
import pdb

# 3p
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

# proj
from log_parser import parser
import utils


########################################################

CONFIG = utils.load_config()["INDEXER"]
LOGGER = utils.get_logger("indexer", f"{CONFIG['HOME_DIR']}/{CONFIG['LOG_PATH']}")
CLIENT = Elasticsearch(hosts=CONFIG["HOSTS"], timeout=30)
MAX_RETRIES = CONFIG["MAX_RETRIES"]


########################################################


def bulk_index(ctr, srvc_files):
    # handle errors... probably collect failed operations to retry later
    LOGGER.info(f"Starting container {ctr}")
    start_time = datetime.now()
    successes = []
    fails = []
    for srvc in srvc_files:
        LOGGER.info(f"Indexing {srvc}")
        for filename in srvc_files[srvc]:
            # LOGGER.info(f"{filename}")
            try:
                tmp = bulk(CLIENT, parser.parse(filename), max_retries=MAX_RETRIES)
            except Exception as e:
                LOGGER.warning(f"{e}: {filename}")
            # LOGGER.info(f"  {tmp}")
            # break
    
    LOGGER.info(f"Container {ctr} indexed in {datetime.now() - start_time}")
    return successes, fails
