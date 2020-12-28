# stdlib
from collections import defaultdict
import pdb

# 3p
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import parallel_bulk

# proj
from log_parser import parser
import utils


########################################################

LOGGER = utils.get_logger("indexer")
CONFIG_ES = utils.load_config()["ELASTICSEARCH"]
CLIENT = Elasticsearch(
    hosts=CONFIG_ES["HOSTS"],
    timeout=CONFIG_ES["TIMEOUT"],
    retry_on_timeout=True,
    max_retries=CONFIG_ES["MAX_RETRIES"],
)
MAX_RETRIES = CONFIG_ES["MAX_RETRIES"]


########################################################


def bulk_index(ctr, srvc_files):
    LOGGER.info(f"[{ctr}] Starting bulk_index for container")
    start_time = datetime.now()
    for srvc in srvc_files:
        fails = defaultdict(list)
        LOGGER.info(f" [{ctr}] [{srvc}] Indexing...")
        for idx, filename in enumerate(srvc_files[srvc]):
            file_start_time = datetime.now()
            actions = parser.parse(filename)
            try:
                for success, info in parallel_bulk(
                    CLIENT,
                    actions,
                    thread_count=4,
                ):
                    if not success:
                        fails[filename].append(info)
            except Exception as e:
                LOGGER.warning(f"{filename}: {e}")
            # try:
            #     res = bulk(CLIENT, parser.parse(filename), max_retries=MAX_RETRIES)
            # except Exception as e:
            #     LOGGER.warning(f"{e}: {filename}")
            # LOGGER.info(f"  {tmp}")
            # break
            LOGGER.debug(
                f"  [{ctr}] [{srvc}] file no. {idx} {filename} finished in {datetime.now() - file_start_time}"
            )
        file_fails = len(fails)
        all_fails = sum(map(lambda l: len(l), fails.values()))
        LOGGER.warning(f" [{ctr}] [{srvc}] found {all_fails} fails in {file_fails} files")
    LOGGER.info(f"[{ctr}] Container indexed in {datetime.now() - start_time}")
    return None
