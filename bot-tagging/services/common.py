# stdlib
from datetime import datetime

# 3p
from elasticsearch_dsl import Q, A

# proj
import es_utils
import utils


###############################################################################


LOGGER = utils.get_logger("services_common", "./logs/services_common.log")

PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

PLACEBO_IDS = [str(_id) for _id in sorted(list(PLACEBOS.keys()))]
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]


###############################################################################


def tag_idx_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in the index pattern's placebo traffic. """
    indices = [idx_ptrn]
    return tag_placebo_ips(tag, idx_ptrn, indices, search_only=search_only)


def tag_other_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in other placebo traffic. """
    indices = [
        ptrn for ptrn in ["nginx-access-*", "ftp-*", "telnet-*", "ssh-*"] if ptrn != idx_ptrn
    ]
    return tag_placebo_ips(tag, idx_ptrn, indices, search_only=search_only)


def tag_placebo_ips(tag, idx_ptrn, indices, search_only=False):
    """ Tag all documents whose client IP was found in other placebo traffic. """
    searches = []
    for other_idx in indices:
        LOGGER.info(f"_tag_placebo_ips idx_ptrn={idx_ptrn} other_idx={other_idx}")
        ips_gen = es_utils.get_ips(other_idx, filter_time=False, tag=None, ctids=PLACEBO_IDS)
        searches.append(ips_gen)
        if not search_only:
            es_utils.tag_ips(idx_ptrn, ips_gen, tag)
    return searches


def tag(tags, idx_ptrn, pipeline, init=False):
    if init:
        es_utils.init_ip_index(idx_ptrn)
    LOGGER.info(f">> {idx_ptrn} pipeline for {tags}")
    pipeline_start = datetime.now()
    for tag, func in pipeline.items():
        if tag not in tags:
            continue
        LOGGER.info(f"{idx_ptrn} tagging: {tag}, {func.__name__}")
        start_time = datetime.now()
        func(tag, idx_ptrn)
        elapsed = datetime.now() - start_time
        LOGGER.info(f"{tag}, {func.__name__} completed in {elapsed.total_seconds()} seconds")
    elapsed = datetime.now() - pipeline_start
    LOGGER.info(f">> {idx_ptrn} pipeline completed in {elapsed.total_seconds()} seconds")


def scan(tags, idx_ptrn, pipeline, aggs, init_data, process_bucket, process_data):
    LOGGER.info(f">> {idx_ptrn} scanning {tags}")
    pipeline_start = datetime.now()
    for tag, func in pipeline.items():
        if tag not in tags:
            continue
        LOGGER.info(f"{idx_ptrn} scanning: {tag}, {func.__name__}")
        data = init_data(tag, idx_ptrn)
        start_time = datetime.now()
        tag_searches = func(tag, idx_ptrn, search_only=True)
        for s_idx, search in enumerate(tag_searches):
            LOGGER.info(f"  search {s_idx}/{len(tag_searches)}: {search.to_dict()}")
            buckets = es_utils.scan_aggs(search, aggs, size=1_000)
            for idx, bucket in enumerate(buckets):
                if idx % 100_000 == 0:
                    LOGGER.info(f"  {idx_ptrn} scan {s_idx} on bucket {idx}...")
                process_bucket(data, bucket)
        elapsed = datetime.now() - start_time
        LOGGER.info(f"yielded after {elapsed.total_seconds()} seconds")
        yield process_data(data)
    elapsed = datetime.now() - pipeline_start
    LOGGER.info(f">> {idx_ptrn} scanning completed in {elapsed.total_seconds()}")