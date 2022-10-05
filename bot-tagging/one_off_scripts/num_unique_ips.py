from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import sys
import pdb

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))

DATA_DIR = MAIN_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOT_DIR = MAIN_DIR / "plots" / "time_series"
PLOT_DIR.mkdir(exist_ok=True)


from elasticsearch_dsl import A, Q, Search
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter, MonthLocator
import numpy as np

from enums import QueryEnum, TagEnum
import utils
import es_utils

IDX_PTRNS = ["nginx-access-*", "ssh-*", "telnet-*", "ftp-*"]
CONFIG = utils.get_config()
NONPLACEBOS = utils.get_nonplacebos()

###############################################################################
def get_num_unique_ips():
    ips = set()
    print("get_num_unique_ips")
    for idx_ptrn in IDX_PTRNS:
        print(f"  on idx_ptrn {idx_ptrn}")
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
        search = search.params(size=1_000)
        for idx, hit in enumerate(search.scan()):
            if idx % 100_000 == 0:
                print(f"    {datetime.now()} on ip {idx} {len(ips)}")
            ips.add(hit.ip)
        print(f"  num_ips {len(ips)}")
    return len(ips)


def get_num_unique_asns():
    asns = set()
    print("get_num_unique_asns")
    for idx_ptrn in IDX_PTRNS:
        print(f"  on idx_ptrn {idx_ptrn}")
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
        asn_agg = {"asn": A("terms", field="geoip.asn")}
        _generator = es_utils.scan_aggs(search, [asn_agg], size=1_000)
        for idx, b in enumerate(_generator):
            asn = b.key.asn
            if idx % 100_000 == 0:
                print(f"    {datetime.now()} on asn {idx} {len(asns)}")
            asns.add(asn)
        print(f"  num_asns {len(asns)}")
    return len(asns)


def get_num_srvc_domain_reqs():
    num_reqs = 0
    nonplacebo_ids = [str(_id) for _id in NONPLACEBOS]
    print("get_num_srvc_domain_reqs")
    for idx_ptrn in IDX_PTRNS:
        print(f"  on idx_ptrn {idx_ptrn}")
        search = es_utils.init_query(
            QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=nonplacebo_ids
        )
        idx_ptrn_reqs = search.count()
        num_reqs += idx_ptrn_reqs
        print(f"    num_reqs {idx_ptrn_reqs} {num_reqs}")
    return num_reqs


def main():
    # start_time = datetime.now()
    # num_unique_ips = get_num_unique_ips()
    # print(f"num_ips={num_unique_ips} ({datetime.now() - start_time})")

    start_time = datetime.now()
    num_unique_asns = get_num_unique_asns()
    print(f"num_unique_asns={num_unique_asns} ({datetime.now() - start_time})")

    start_time = datetime.now()
    num_srvc_domain_reqs = get_num_srvc_domain_reqs()
    print(f"num_srvc_domain_reqs={num_srvc_domain_reqs} ({datetime.now() - start_time})")


if __name__ == "__main__":
    main()