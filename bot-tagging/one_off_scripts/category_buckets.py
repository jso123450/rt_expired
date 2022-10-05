import pandas as pd

csv_file = "/home/ubuntu/repos/rt_expired/data/domain-profile.csv"
df = pd.read_csv(csv_file)
traffic_buckets = sorted(df.ports_traffic_bucket.unique())
traffic_dfs = [df[df.ports_traffic_bucket == bkt] for bkt in traffic_buckets]

conf_buckets = sorted(df.confidence.unique())
conf_dfs = [df[df.confidence == conf] for conf in conf_buckets]

categories = {
    "gambling": ["gambling"],
    "crime": ["contrabands", "malicious", "forgery"],
    "streaming": ["streaming"],
    "adult": ["pornography", "prostitution"],
    "company": ["company"],
    "api": ["api"],
    "downloads": ["downloads"],
    "non-http": ["non-http"],
    "other": ["other", "forum"],
    "unknown": ["unknown"],
}


def get_num_buckets_category(dfs, subsume):
    return [df[df.service_type.isin(subsume)].shape[0] for df in dfs]


def get_num_buckets_total(results, num_bkts):
    return [sum([results[k][i] for k in results]) for i in range(num_bkts)]

# def augment_non_http(df):
#     non_http = [""]


traffic_bkts_cat = {c: get_num_buckets_category(traffic_dfs, categories[c]) for c in categories}
traffic_bkts_total = get_num_buckets_total(traffic_bkts_cat, len(traffic_buckets))

conf_bkts_cat = {c: get_num_buckets_category(conf_dfs, categories[c]) for c in categories}
conf_bkts_total = get_num_buckets_total(conf_bkts_cat, len(conf_buckets))

