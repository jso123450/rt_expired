import sys

sys.path.append("/home/ubuntu/repos/rt_expired/bot-tagging")


from elasticsearch_dsl import Q

from enums import QueryEnum, TagEnum
import utils
import es_utils


IP_IDX = "ips-nginx-access"
TAG = "residual-path"  # change
TAG_TYPE = TagEnum.USER  # change
FILTER_KEY = "user_filter_tags"
CONFIG = utils.get_config()

ubq = es_utils.init_query(QueryEnum.UBQ, IP_IDX, filter_time=False)
query = Q("bool", filter=[Q("match", **{FILTER_KEY: TAG})])
ubq = ubq.query(query)
ubq = ubq.script(source=es_utils.get_tag_script(TAG_TYPE, add=False), params={"tag": TAG})
ubq = ubq.params(conflicts="proceed")
print(ubq.to_dict())
response = ubq.execute()
print(response.to_dict())