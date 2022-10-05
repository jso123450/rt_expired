from collections import defaultdict
from datetime import datetime
import sys
from urllib.parse import urlparse

sys.path.append("/home/ubuntu/repos/rt_expired/bot-tagging")

from elasticsearch_dsl import A, Q

from enums import QueryEnum, TagEnum
import utils
import es_utils

IDX_PTRN = "nginx-access-*"
CONFIG = utils.get_config()
NONPLACEBOS = utils.get_nonplacebos()
CTR = "628"
CTR_DOMAIN = NONPLACEBOS[int(CTR)]["domain"]
CTR_IP = NONPLACEBOS[int(CTR)]["ip"]

search = es_utils.init_query(QueryEnum.SEARCH, IDX_PTRN, filter_time=True, ctids=[CTR])
referrer_q = Q(
    "bool",
    filter=[
        Q("term", log__container__keyword=CTR),
        Q("exists", field="nginx.referrer"),
    ],
    must_not=[
        Q("term", nginx__referrer__keyword=""),
        Q("term", nginx__referrer__keyword="-"),
        Q("wildcard", nginx__referrer__keyword=f"*{CTR_DOMAIN}*"),
        Q("wildcard", nginx__referrer__keyword=f"*{CTR_IP}*"),
    ],
)
search = search.query(referrer_q)
referrer_agg = {"referrer": A("terms", field="nginx.referrer.keyword")}
_generator = es_utils.scan_aggs(search, [referrer_agg], size=1_000)
referrers = defaultdict(int)
start_time = datetime.now()
for idx, bucket in enumerate(_generator):
    if idx % 100 == 0:
        print(f"  on bucket {idx} ({datetime.now() - start_time})")
    referrer = bucket.key.referrer
    count = bucket.doc_count
    parsed = urlparse(referrer)
    referrers[parsed.netloc] += count
print(f"finished in {datetime.now() - start_time}")
print(referrers)