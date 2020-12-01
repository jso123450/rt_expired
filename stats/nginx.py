# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from IPython import get_ipython

get_ipython().run_line_magic("load_ext", "autotime")

# %%
from collections import defaultdict
from datetime import datetime
import logging
from pathlib import Path
import pdb
import re

from elasticsearch_dsl import A
import pandas as pd
import matplotlib.pyplot as plt
import tldextract

# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils
import plot_utils

# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()
INDEX = "nginx-access-*"

# constants
SEP = CONFIG["IO"]["CSV_SEP"]
TRAP_PATH = "/trap/"
ILLEGAL_URL_CHARS = [" ", "|", '"', "<", ">", "^", "`", "{", "}", "~"]
ILLEGAL_URL_REGEX = "|".join(map(re.escape, ILLEGAL_URL_CHARS))
ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

# artifacts
ARTIFACT_DIR = Path(CONFIG["ARTIFACT_DIR"]) / "nginx"
HOME_DIR = Path(CONFIG["HOME_DIR"])
DATA_DIR = ARTIFACT_DIR / "es"
PLOTS_DIR = ARTIFACT_DIR / "plots"
FILTERED_DIR = ARTIFACT_DIR / "filtered"
NGINX_IP_PATHS_DF = DATA_DIR / "nginx_ip_paths_nonplacebos_methods.csv"
NGINX_REQS_DF = DATA_DIR / "nginx_reqs.csv"
NGINX_IPS = DATA_DIR / "nginx_ips.csv"
BOT_IPS_FILE = DATA_DIR / "nginx_bot_ips.txt"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
FILTERED_DIR.mkdir(parents=True, exist_ok=True)

# globals
LOGGER = utils.get_logger("nginx_stats", ARTIFACT_DIR / "nginx.log", logging.INFO)

# %% utils
def get_unique_paths(df):
    unique_paths = defaultdict(int)
    paths_series = df.value_counts(subset=["path"])
    for obj in paths_series.iteritems():
        path = obj[0][0]
        count = obj[1]
        without_query = path if path.find("?") == -1 else path[: path.find("?")]
        unique_paths[without_query] += count
    return unique_paths


# %%
def get_nginx_reqs_agg(idx_ptrn, csv):
    def _process_bucket(bucket, **kwargs):
        ctid = bucket.key.ctid
        client_ip = bucket.key.ip
        path = bucket.key.path
        method = bucket.key.method
        ip, domain = es_utils.get_ip_domain(bucket.key.ctid, CTRS)
        if ip is None or domain is None:  # test container
            return
        row = [ctid, client_ip, path, method, str(bucket.doc_count)]
        output = f"{SEP.join(row)}\n"
        return output

    # params
    usecols = ["id", "client_ip", "path", "method"]
    dtype = {"id": "uint16", "client_ip": "string", "path": "string", "method": "category"}
    source_aggs = [
        {"ctid": A("terms", field="container.id.keyword")},
        {"ip": A("terms", field=es_utils.get_ip_field(INDEX))},
        {"path": A("terms", field="nginx.access.url.keyword")},
        {"method": A("terms", field="nginx.access.method.keyword")},
    ]
    source_aggs_map = {idx_ptrn: source_aggs}
    cols = ["id", "client_ip", "path", "method", "count"]
    nonplacebos = sorted(list(NONPLACEBOS.keys()))
    nonplacebos = [str(_id) for _id in nonplacebos]

    # load df
    df = es_utils.query_scan_idx(
        csv,
        [idx_ptrn],
        _process_bucket,
        cols,
        usecols,
        dtype,
        source_aggs_map=source_aggs_map,
        filter_time=True,
        ctids=nonplacebos,
    )
    return df


# %%
def filter_illegal_tokens(df):
    illegal_tokens = df[df.path.str.contains(ILLEGAL_URL_REGEX)]
    non_illegal_tokens = df[~df.path.str.contains(ILLEGAL_URL_REGEX)]
    return non_illegal_tokens, illegal_tokens


def filter_df_1(df, placebo_ips, idx_placebos, other_bot_ips):
    nonplacebo_ips = df[~df["client_ip"].isin(placebo_ips)]
    nonplacebo_bot_ips = df[df["client_ip"].isin(placebo_ips)]

    filtered_2 = nonplacebo_ips  # requests with IPs not found contacting placebos

    trap_df = filtered_2[
        filtered_2["path"].str.find(TRAP_PATH) > -1
    ]  # requests that accessed a trap path
    filtered_3 = filtered_2[
        filtered_2["path"].str.find(TRAP_PATH) == -1
    ]  # requests that did not access a trap path
    filtered_3 = filtered_3[
        ~filtered_3["client_ip"].isin(trap_df.client_ip.unique())
    ]  # filter out requests from IPs that accessed traps
    # filtered_4, illegal_token_rows = filter_illegal_tokens(filtered_3)

    filtered_4 = filtered_3[~filtered_3["client_ip"].isin(other_bot_ips)]
    other_bot_ip_rows = filtered_3[filtered_3["client_ip"].isin(other_bot_ips)]

    filter_lvl_dfs = [filtered_4, other_bot_ip_rows, trap_df, nonplacebo_bot_ips, idx_placebos]
    labels = [
        "Unique Client IPs",
        "Filtered by other services' bot IPs",
        "Filtered by trap paths",
        "Filtered by placebo IPs for any service",
        "Filtered by placebo domain",
    ]

    return filter_lvl_dfs, labels


# %%
# df["path_len"] = df["path"].apply(lambda x: len(x))


# tmp = pd.concat([filtered_1_df, placebo_df])
# tmp = pd.melt(tmp, id_vars=["FilterLvl"], var_name=["Filter Level"], value_vars=["path_len"])
# ax = sns.boxplot(x="FilterLvl", y="value", hue="Filter Level", data=tmp)
# plt.title("Request Path Length Distribution")
# plt.savefig(PLOTS_DIR / "path_length_boxplot.png")

# # 30467
# # 33710

# %%
def bot_filter_pipeline():
    # get source df
    df = get_nginx_reqs_agg(INDEX, NGINX_IP_PATHS_DF)

    # get placebo IPs
    placebos = sorted(list(PLACEBOS.keys()))
    placebos = [str(_id) for _id in placebos]
    placebo_srvc_unique_ips = es_utils.get_srvc_unique_ips(
        es_utils.PLACEBO_SRVC_UNIQUE_IPS_DF, ctids=placebos, filter_time=False
    )
    # all_srvc_unique_ips = es_utils.get_srvc_unique_ips(es_utils.ALL_SRVC_UNIQUE_IPS_DF, filter_time=False)
    # placebos, _, _, _ = es_utils.filter_placebo_ips(idx_placebos)
    placebo_ips = placebo_srvc_unique_ips.client_ip.unique()
    idx_placebos = placebo_srvc_unique_ips[placebo_srvc_unique_ips.idx_ptrn == INDEX]
    del placebo_srvc_unique_ips
    del placebos

    LOGGER.info(f"Loaded placebo IPs {len(placebo_ips)}")

    # get other bot IPs
    other_bot_ips = es_utils.get_other_bot_ips(INDEX)

    # run pipeline
    filter_lvl_dfs, labels = filter_df_1(df, placebo_ips, idx_placebos, other_bot_ips)
    LOGGER.info(f"Filtered df.")

    ## filter_lvl_dfs = [final, filtered_from_other_idx, ...]
    es_utils.save_bot_ips(filter_lvl_dfs[2:], BOT_IPS_FILE)

    srvc = "nginx"
    tmp = plot_utils.plot_ip_counts(
        filter_lvl_dfs, legend=labels, _file=PLOTS_DIR / f"{srvc}-filter-bars.png"
    )
    plot_utils.plot_sankey_filters(
        filter_lvl_dfs,
        node_labels=[
            "F0",
            "Web Placebo Servers",
            "F1",
            "All Services' Placebo IPs",
            "F2",
            "Bot Trap Paths",
            # "F3", "Illegal URL Chars",
            "F3",
            "Other Services' Bot IPs",
            "F4",
        ],
        _file=PLOTS_DIR / f"{srvc}-sankey.html",
    )
    return tmp, filter_lvl_dfs


# %%
def get_path_breakdown(df):
    LOGGER.info(f"Getting path breakdown...")
    path_ips = defaultdict(lambda: defaultdict(list))
    for row in df.itertuples():
        path_ips[row.path]["ips"].append(row.client_ip)
        path_ips[row.path]["ctids"].append(row.id)
        path_ips[row.path]["methods"].append(row.method)
    rows = []
    for path, _dict in path_ips.items():
        ips = _dict["ips"]
        ctids = _dict["ctids"]
        methods = _dict["methods"]
        frac_get = methods.count("GET") / len(methods)
        frac_post = methods.count("POST") / len(methods)
        row = [
            path,
            len(set(ips)),
            len(ips),
            len(set(ctids)),
            frac_get,
            frac_post,
            set(methods),
            set(ips),
            set(ctids),
        ]
        rows.append(row)
    tmp = pd.DataFrame(
        rows,
        columns=[
            "path",
            "unique_ips",
            "num_reqs",
            "unique_ctids",
            "frac_get",
            "frac_post",
            "methods",
            "ips",
            "ctids",
        ],
    )
    return tmp


def get_ip_breakdown(df):
    LOGGER.info(f"Getting IP breakdown...")
    ip_info = defaultdict(lambda: defaultdict(list))
    for row in df.itertuples():
        ip_info[row.client_ip]["paths"].append(row.path)
        ip_info[row.client_ip]["ctids"].append(row.id)
        ip_info[row.client_ip]["methods"].append(row.method)
    rows = []
    for ip, _dict in ip_info.items():
        paths = _dict["paths"]
        ctids = _dict["ctids"]
        methods = _dict["methods"]
        frac_get = methods.count("GET") / len(methods)
        frac_post = methods.count("POST") / len(methods)
        row = [
            ip,
            len(set(ctids)),
            len(set(paths)),
            len(paths),
            frac_get,
            frac_post,
            set(ctids),
            set(paths),
            set(methods),
        ]
        rows.append(row)
    tmp = pd.DataFrame(
        rows,
        columns=[
            "client_ip",
            "unique_ctids",
            "unique_paths",
            "num_reqs",
            "frac_get",
            "frac_post",
            "ctids",
            "paths",
            "methods",
        ],
    )
    return tmp


def plot_col_distribution(df, col, title, xlabel, ylabel, _file):
    LOGGER.info(f"Plotting {title} and saving to {_file}.")
    plt.hist(df[col], bins="auto")
    fig = plt.gcf()
    fig.patch.set_facecolor("white")
    plt.yscale("log")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)

    plt.savefig(PLOTS_DIR / f"{_file}")
    plt.clf()


def plot_path_distribution(df):
    cols = ["num_reqs", "unique_ips", "unique_ctids"]
    num_strs = ["Requests", "IPs", "Containers"]
    for idx, col in enumerate(cols):
        num_str = num_strs[idx]
        plot_col_distribution(
            df,
            col=col,
            title=f"Number of {num_str} for URLs",
            xlabel=f"Number of {num_str} for a URL",
            ylabel=f"Frequency",
            _file=PLOTS_DIR / f"path-{col}-dist.png",
        )


def plot_ip_distribution(df):
    cols = ["num_reqs", "unique_ctids", "unique_paths"]
    num_strs = ["Requests", "Containers", "Paths"]
    for idx, col in enumerate(cols):
        num_str = num_strs[idx]
        plot_col_distribution(
            df,
            col=col,
            title=f"Number of {num_str} for IPs",
            xlabel=f"Number of {num_str} for an IP",
            ylabel=f"Frequency",
            _file=PLOTS_DIR / f"ip-{col}-dist.png",
        )


# %%
df = get_nginx_reqs_agg(INDEX, NGINX_IP_PATHS_DF)
# tmp, filtered = bot_filter_pipeline()
# filtered[0].to_csv(FILTERED_DIR / "nginx-filtered.csv",
#     index=False, header=True
# )

# path_breakdown = get_path_breakdown(filtered[0])
# ip_breakdown = get_ip_breakdown(filtered[0])

# path_breakdown.to_csv(FILTERED_DIR / "nginx-path-breakdown.csv",
#     index=False, header=True
# )
# ip_breakdown.to_csv(FILTERED_DIR / "nginx-ip-breakdown.csv",
#     index=False, header=True
# )
# plot_path_distribution(path_breakdown)
# plot_ip_distribution(ip_breakdown)

# %%
def filter_init_setup(df):
    init_paths = df[df.path.str.contains("\.init\.|setup")]
    non_bots = df[~df.client_ip.isin(init_paths.client_ip.unique())]
    return non_bots, init_paths


def filter_shell(df):
    shell = df[df.path.str.contains("shell|console|wget")]
    shell = shell[~shell.path.str.contains("tattoo", regex=False)]
    non_shell = df[~df.client_ip.isin(shell.client_ip.unique())]
    return non_shell, shell


def filter_logins(df):
    logins = df[(df.path.str.contains("login")) & (df.method == "POST")]
    non_logins = df[~df.client_ip.isin(logins.client_ip.unique())]
    return non_logins, logins


def filter_domains(df):
    def _has_domain(row):
        extract = tldextract.extract(row.path)
        has_domain = len(extract.subdomain) > 0 or len(extract.domain) > 0
        if has_domain:
            # //static/black.png?t=1566584769
            # ExtractResult(subdomain='', domain='static', suffix='')
            is_ip = len(extract.domain.split(".")) == 4
            has_domain = is_ip or len(extract.suffix) > 0
        return has_domain

    df["tmp"] = df.apply(_has_domain, axis=1)
    domain_paths = df[df.tmp]
    non_domain_paths = df[~df.client_ip.isin(domain_paths.client_ip.unique())]
    domain_paths = domain_paths.drop(labels=["tmp"], axis=1)
    non_domain_paths = non_domain_paths.drop(labels=["tmp"], axis=1)
    return non_domain_paths, domain_paths


def filter_path_traversal(df):
    def _is_path_traversal(path):
        return "../" in path or "..\\" in path

    df["tmp"] = df.path.apply(_is_path_traversal)
    path_traversals = df[df.tmp]
    non_path_traversals = df[~df.client_ip.isin(path_traversals.client_ip.unique())]
    path_traversals = path_traversals.drop(labels=["tmp"], axis=1)
    non_path_traversals = non_path_traversals.drop(labels=["tmp"], axis=1)
    return non_path_traversals, path_traversals


def filter_xmlrpc(df):
    xmlrpc_paths = df[df.path.str.contains("xmlrpc")]
    non_xmlrpc = df[~df.client_ip.isin(xmlrpc_paths.client_ip.unique())]
    return non_xmlrpc, xmlrpc_paths


def _filter_exploits(df, exploit_keys):
    exploit_path_indices = set()
    for idx, exploit in enumerate(exploit_keys):
        if idx % 100 == 0:
            LOGGER.info(f"_filter_exploits {idx} of {len(exploit_keys)}")
        exploited_rows = df[df.path.str.contains(re.escape(exploit))]
        exploit_path_indices.update(set(exploited_rows.index))
    exploit_paths = df.loc[list(exploit_path_indices)]
    non_exploit_paths = df[~df.client_ip.isin(exploit_paths.client_ip.unique())]
    return non_exploit_paths, exploit_paths


def filter_bot_endpoints(df):
    bot_endpoints = utils.get_bot_endpoints()
    return _filter_exploits(df, bot_endpoints)


# def filter_wp_exploits(df):
#     exploit_keys = [
#         "admin-ajax\.php",  # also used as heartbeat
#     ]
#     return _filter_exploits(df, exploit_keys)


# def filter_phpunit_exploits(df):
#     exploit_keys = [
#         "eval-stdin\.php",
#     ]
#     return _filter_exploits(df, exploit_keys)


def filter_df_2(df):
    df_1, init_paths = filter_init_setup(df)
    df_2, shell_paths = filter_shell(df_1)

    config_paths = df_2[df_2.path.str.contains("config|\.cfg|/cfg")]
    df_3 = df_2[~df_2.client_ip.isin(config_paths.client_ip.unique())]
    df_4, login_paths = filter_logins(df_3)

    git_paths = df_4[df_4.path.str.contains(".git", regex=False)]
    df_5 = df_4[~df_4.client_ip.isin(git_paths.client_ip.unique())]
    df_6, domain_paths = filter_domains(df_5)
    df_7, path_traversals = filter_path_traversal(df_6)
    df_8, xmlrpc_paths = filter_xmlrpc(df_7)
    # df_9, wp_exploits = filter_wp_exploits(df_8)
    # df_10, phpunit_exploits = filter_phpunit_exploits(df_9)
    df_9, bot_endpoints = filter_bot_endpoints(df_8)

    filter_lvl_dfs = [
        df_9,
        bot_endpoints,
        # phpunit_exploits,
        # wp_exploits,
        xmlrpc_paths,
        path_traversals,
        domain_paths,
        git_paths,
        login_paths,
        config_paths,
        shell_paths,
        init_paths,
    ]
    for idx, _df in enumerate(filter_lvl_dfs):
        _df.to_csv(FILTERED_DIR / f"filtered-{idx:02}.csv", index=False, header=True)
    labels = [
        "Unique Client IPs",
        "Bot Endpoints",
        "XMLRPC",
        "Path Traversals",
        "Domain",
        ".git",
        "login",
        "config|.cfg",
        "shell|console",
        ".init.|setup",
    ]
    return filter_lvl_dfs, labels


def print_ips(filter_lvl_dfs, labels):
    for idx, label in enumerate(labels):
        num_ips = filter_lvl_dfs[idx].client_ip.nunique()
        print(f"Label {idx} {label}: {num_ips} IPs.")


# %%
# df = get_nginx_reqs_agg(INDEX, NGINX_IP_PATHS_DF)

filtered = pd.read_csv(FILTERED_DIR / "nginx-filtered.csv", header=0)
# path_breakdown = pd.read_csv(FILTERED_DIR / "nginx-path-breakdown.csv", header=0)
# ip_breakdown = pd.read_csv(FILTERED_DIR / "nginx-ip-breakdown.csv", header=0)

# %%
filter_lvl_dfs, labels = filter_df_2(filtered)
print_ips(filter_lvl_dfs, labels)
tmp_plot_ip_counts = plot_utils.plot_ip_counts(
    filter_lvl_dfs, legend=labels, _file=PLOTS_DIR / f"nginx-filter2-bars.png"
)

final_filtered = filter_lvl_dfs[0]
path_breakdown = get_path_breakdown(final_filtered)
ip_breakdown = get_ip_breakdown(final_filtered)

path_breakdown.to_csv(FILTERED_DIR / "filtered-0-path-breakdown.csv", index=False, header=True)
ip_breakdown.to_csv(FILTERED_DIR / "filtered-0-ip-breakdown.csv", index=False, header=True)

# plot_path_distribution(path_breakdown)
# plot_ip_distribution(ip_breakdown)

# %%

non_710_833 = final_filtered[(final_filtered.id != 710) & (final_filtered.id != 833)]

non_710_833_path_breakdown = get_path_breakdown(non_710_833)
non_710_833_ip_breakdown = get_ip_breakdown(non_710_833)
non_710_833.to_csv(FILTERED_DIR / "non_710_833.csv", index=False)
non_710_833_path_breakdown.to_csv(
    FILTERED_DIR / "non_710_833-path-breakdown.csv",
    index=False,
)
non_710_833_ip_breakdown.to_csv(
    FILTERED_DIR / "non_710_833-ip-breakdown.csv",
    index=False,
)

tmp = filtered[(filtered.id == 710) | (filtered.id == 833)]
tmp = tmp[
    (tmp.path.str.contains("/bots"))
    | (tmp.path.str.contains("/api"))
    | (tmp.path.str.contains("/log"))
    | (tmp.path.str.contains("/sync"))
]
same_ips = non_710_833[non_710_833.client_ip.isin(tmp.client_ip.unique())]

# %%

# bots_710 = filter_lvl_dfs[0]
# bots_710 = bots_710[(bots_710.id==710) & ((bots_710.path.str.contains("/bots")) | (bots_710.path.str.contains("/api")))]
# non_bots_710 = filter_lvl_dfs[0]
# non_bots_710 = non_bots_710[~non_bots_710.client_ip.isin(bots_710.client_ip.unique())]

# non_bots_710.to_csv(FILTERED_DIR / "non_bots_710.csv", index=False)
# non_710_path_breakdown = get_path_breakdown(non_bots_710)
# non_710_ip_breakdown = get_ip_breakdown(non_bots_710)

# non_710_path_breakdown.to_csv(FILTERED_DIR / "non_bots_710-path-breakdown.csv",
#     index=False, header=True
# )
# non_710_ip_breakdown.to_csv(FILTERED_DIR / "non_bots_710-ip-breakdown.csv",
#     index=False, header=True
# )

# %%
def get_nginx_reqs(csv):
    def _process_hit(hit, **kwargs):
        try:
            ctid = hit.container.id
            timestamp = hit["@timestamp"]
            # timestamp = timestamp[:-1] if timestamp[-1] == "Z" else timestamp
            # timestamp = datetime.strptime(timestamp, ISO_FORMAT)
            client_ip = hit.nginx.access.remote_ip
            path = hit.nginx.access.url

            ip, domain = es_utils.get_ip_domain(ctid, CTRS)
            if ip is None or domain is None:  # test container
                return
            row = [ctid, timestamp, client_ip, path]
            output = f"{SEP.join(row)}\n"
            return output
        except AttributeError as e:
            # malformatted
            return None

    # params
    cols = ["id", "timestamp", "client_ip", "path"]
    usecols = cols
    date_cols = ["timestamp"]
    dtype = {"id": "uint16", "client_ip": "string", "path": "string"}
    nonplacebos = sorted(list(NONPLACEBOS.keys()))
    nonplacebos = [str(_id) for _id in nonplacebos]

    # load df
    df = es_utils.query_scan_idx(
        csv,
        [INDEX],
        _process_hit,
        cols,
        usecols,
        dtype,
        source_aggs_map=None,
        filter_time=True,
        ctids=nonplacebos,
        sort_timestamp=True,
        date_cols=date_cols,
    )
    return df


def get_nginx_sess_dur():
    # for each hit,
    #   1) for each active session, check if hit.meta.timestamp - time of last req
    #       >= some threshold (e.g. 10 mins)
    #   2) for all sessions that have ended, output a line of the format
    #       ip {SEP} start {SEP} end {SEP} reqs           {SEP} flags
    #                                      {ctid}/req1...       trap...
    pass


# %%
# bot_ips = es_utils.get_other_bot_ips("*")
# nginx_reqs = get_nginx_reqs(NGINX_REQS_DF)