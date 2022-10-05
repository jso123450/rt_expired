# stdlib
from collections import defaultdict
import json
from pathlib import Path
import pdb

# 3p
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import numpy as np
from elasticsearch_dsl import A

# proj
from enums import QueryEnum
from services import nginx  # , ftp_telnet
import utils
import es_utils
import plot_utils


###############################################################################

LOGGER = utils.get_logger("analysis")
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in NONPLACEBOS]

# IDX_PTRN_TAGS = {
#     "nginx-access-*": nginx.BOT_TAG_PIPELINE.keys(),
#     "ftp-*": [],
#     "telnet-*": [],
#     "ssh-*": [],
# }
LOG_PROGRESS = {"nginx-access-*": 100_000, "ftp-*": 1_000, "telnet-*": 10_000, "ssh-*": 10_000}

IDX_PTRN_TO_SERVICE = {
    "nginx-access-*": "web",
    "ftp-*": "ftp",
    "ssh-*": "ssh",
    "telnet-*": "telnet",
}
PLOT_DIR = Path("plots/ctr_status")
PLOT_DIR.mkdir(parents=True, exist_ok=True)

###############################################################################


def load_status(status_file, key):
    status = {}
    try:
        with open(status_file, "r") as f:
            for line in f:
                if len(line.strip()) == 0:
                    continue
                o = json.loads(line)
                key_val = o[key]
                del o[key]
                status[key_val] = o
    except FileNotFoundError:
        pass
    return status


def load_ctr_status(status_file):
    return load_status(status_file, "ctid")


# def aggregate_num_tagged(idx_ptrn, ctr_status):
#     idx_tags = IDX_PTRN_TAGS[idx_ptrn]

#     rows = []
#     cols = ["ctid", *idx_tags, "untagged"]
#     for ctid, ctr_info in ctr_status.items():
#         tag_ips = [ctr_info["tags_to_ips"].get(tag, []) for tag in idx_tags]
#         num_tag_ips = [len(ips) for ips in tag_ips]
#         untagged = ctr_info["untagged"]
#         row = [ctid, *num_tag_ips, untagged]
#         rows.append(row)
#     return pd.DataFrame(rows, columns=cols)


# def plot_ctr_status(idx_ptrn, status_file):
#     ctr_status = load_ctr_status(status_file)
#     df = aggregate_num_tagged(ctr_status)
#     pdb.set_trace()
#     print("hi")


###############################################################################


def _get_ctr_status(idx_ptrn, ctr):
    LOGGER.info(f"ctr status for {idx_ptrn} {ctr}")
    ips_gen = es_utils.get_ips(idx_ptrn, filter_time=True, tag=None, ctids=[ctr])
    stats, num_bot_tags, num_user_tags = es_utils.get_tagged_ips(idx_ptrn, ips_gen)
    ctr_status = dict(ctid=ctr, stats=stats, num_bot_tags=num_bot_tags, num_user_tags=num_user_tags)
    return ctr_status


# def get_containers_status(idx_ptrn, results_file):
#     status = load_ctr_status(results_file)
#     sorted_ctrs = utils.get_sorted_containers()
#     ctrs = [ctr for ctr in sorted_ctrs if int(ctr) in NONPLACEBOS]
#     with open(results_file, "a+") as f:
#         for ctr in ctrs:
#             if ctr in status:
#                 continue
#             ctr_status = _get_ctr_status(idx_ptrn, ctr)
#             out = f"{json.dumps(ctr_status)}\n"
#             f.write(out)


def _get_ctr_status_2(idx_ptrn, ip_status, ip_tags, ctr):
    LOGGER.info(f"ctr status for {idx_ptrn} {ctr}")
    # ips_gen = es_utils.get_ips(idx_ptrn, filter_time=True, tag=None, ctids=[ctr])
    stats, num_bot_tags, num_user_tags = es_utils.get_tagged_ips_ctr(
        idx_ptrn, ip_status, ip_tags, ctr
    )
    ctr_status = dict(ctid=ctr, stats=stats, num_bot_tags=num_bot_tags, num_user_tags=num_user_tags)
    return ctr_status


def get_containers_status(idx_ptrn, results_file):
    status = load_ctr_status(results_file)
    sorted_ctrs = utils.get_sorted_containers()
    ctrs = [ctr for ctr in sorted_ctrs if int(ctr) in NONPLACEBOS]
    # ctrs = list(reversed(ctrs))
    with open(results_file, "a+") as f:
        for ctr in ctrs:
            if ctr in status:
                continue
            if ctr == "657":
                ip_status, ip_tags = es_utils.get_ip_status(idx_ptrn)
                ctr_status = _get_ctr_status_2(idx_ptrn, ip_status, ip_tags, ctr)
            else:
                ctr_status = _get_ctr_status(idx_ptrn, ctr)
            out = f"{json.dumps(ctr_status)}\n"
            f.write(out)


def get_tag_ctr_status_df(results_file):
    status = load_ctr_status(results_file)
    bot_tags = set()
    user_tags = set()
    for (_, ctid_info) in status.items():
        bot_tags.update(ctid_info["num_bot_tags"].keys())
        user_tags.update(ctid_info["num_user_tags"].keys())
    rows = []
    bot_tags = list(bot_tags)
    user_tags = list(user_tags)
    for (ctid, ctid_info) in status.items():
        ctid_int = int(ctid)
        ctid_stats = ctid_info["stats"]
        untagged = ctid_stats.get("untagged", 0)
        bot = ctid_stats.get("bot", 0)
        user = ctid_stats.get("user", 0)
        both = ctid_stats.get("both", 0)
        num_bot_tags = ctid_info["num_bot_tags"]
        num_user_tags = ctid_info["num_user_tags"]
        row = [ctid_int, untagged, bot, user, both]
        for bot_tag in bot_tags:
            num_bot_tag = num_bot_tags.get(bot_tag, 0)
            row.append(num_bot_tag)
        for user_tag in user_tags:
            num_user_tag = num_user_tags.get(user_tag, 0)
            row.append(num_user_tag)
        rows.append(row)
    bot_tags = [f"bot_{tag}" for tag in bot_tags]
    user_tags = [f"user_{tag}" for tag in user_tags]
    cols = ["ctid", "untagged", "bot", "user", "both", *bot_tags, *user_tags]
    df = pd.DataFrame(rows, columns=cols)
    dtype = {
        "ctid": "category",
        "untagged": "int64",
        "bot": "int64",
        "user": "int64",
        "both": "int64",
    }
    dtype.update({_key: "int64" for _key in [*bot_tags, *user_tags]})
    df = df.astype(dtype)
    return df


def aggregate_blocklist_cols(df):
    cols = [col for col in df.columns if col.find("bot_bl_") == 0]
    blocklist_ipsets = []
    for row in df.itertuples():
        ctid_blocklist_total = 0
        asdict = row._asdict()
        for col in cols:
            ctid_blocklist_total += asdict.get(col, 0)
        blocklist_ipsets.append(ctid_blocklist_total)
    df["bot_blocklist_ipsets"] = blocklist_ipsets
    return df


def plot_containers_status(idx_ptrn, results_file):
    def _plot_ctr_status(ax, row, cols, prefixed=True, rotation=45, width=0.35):
        _func = lambda x, y: x[x.find("_") + 1 :] if y else x
        labels = [_func(col, prefixed) for col in cols]
        x = np.arange(len(labels))
        ax.bar(x, row, width)
        ax.set_xlabel("Filters")
        ax.set_ylabel("Number of Unique IPs")
        ax.set_yscale("log")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=rotation, ha="right")
        plot_utils.style_grid(ax)

    def _plot_overall_status(ax, df, ctid):
        cols = ["untagged", "bot", "user", "both"]
        row = df[df.ctid == ctid][cols].iloc[0].tolist()
        _plot_ctr_status(ax, row, cols, prefixed=False)
        ax.set_title(f"Overall Status")

    def _plot_tag_status(ax, df, ctid, bot=True):
        excluded_cols = set(["ctid", "untagged", "bot", "user", "both"])
        excluded_prefix = ["user_", "bot_bl_"] if bot else ["bot_"]
        cols = []
        for col1 in df.columns:
            use = col1 not in excluded_cols
            if use:
                for prefix in excluded_prefix:
                    use = use and prefix not in col1
            if use:
                cols.append(col1)
        modifier = "Bot" if bot else "User"
        row = df[df.ctid == ctid][cols].iloc[0].tolist()
        _plot_ctr_status(ax, row, cols)
        ax.set_title(f"{modifier} Filter Status")

    LOGGER.info(f"plot_containers_status {idx_ptrn} {results_file}...")
    df = get_tag_ctr_status_df(results_file)
    df = aggregate_blocklist_cols(df)
    for idx, ctid in enumerate(df.ctid):
        if idx % 25 == 0:
            LOGGER.debug(f"  plotting ctr {ctid} ({idx}/{len(df.ctid)})")
        domain = NONPLACEBOS[int(ctid)]["domain"]
        plot_file = PLOT_DIR / f"{ctid}-ctr_status.png"
        fig = plt.figure(figsize=(6, 18))
        gs = GridSpec(3, 1, figure=fig)
        axes = []
        for i in range(3):
            ax = fig.add_subplot(gs[i, :])
            axes.append(ax)
        _plot_overall_status(axes[0], df, ctid)
        _plot_tag_status(axes[1], df, ctid, bot=True)
        _plot_tag_status(axes[2], df, ctid, bot=False)
        fig.suptitle(f"IP Filtering Status for {idx_ptrn} {ctid} {domain}")
        plt.tight_layout()
        plt.savefig(plot_file, facecolor="white")
        plt.close(fig)
    LOGGER.info(f"Finished plot_containers_status...")


def plot_hist_filtered(idx_ptrn, results_file):
    def _get_ctid_val(df, col_name, which="mean"):
        ser = df[col_name]
        val = None
        if which == "mean":
            val = ser.mean()
        elif which == "median":
            val = ser.median()
        elif which == "min":
            val = ser.min()
        elif which == "max":
            val = ser.max()
        else:
            raise RuntimeError(f"Unknown value for 'which': {which}")
        ctid = df[df[col_name] == val].ctid.tolist()
        assert len(ctid) <= 1
        retval1 = ctid[0] if len(ctid) == 1 else None
        return retval1, val

    LOGGER.info(f"plot_hist_filtered {idx_ptrn} {results_file}...")
    df = get_tag_ctr_status_df(results_file)
    df = aggregate_blocklist_cols(df)

    _func = lambda x: (x.bot + x.both) / (x.bot + x.both + x.user + x.untagged)
    col_name = "filtered_percent"
    df[col_name] = df.apply(_func, axis=1)
    df = df.dropna()
    df = df.sort_values(by=["filtered_percent"], ascending=True)
    # thresh = 0.9  # 0.6 or 0.9
    # df = df[df.filtered_percent > thresh]  # filter low outliers
    # pdb.set_trace()

    # plot
    fig, ax = plt.subplots(nrows=1, ncols=1)
    ax.hist(df[col_name], bins="auto")

    # annotate
    _, max_ylim = plt.ylim()
    median_ctid, median_val = _get_ctid_val(df, col_name, which="median")
    min_ctid, min_val = _get_ctid_val(df, col_name, which="min")
    plt.axvline(median_val, color="k", linestyle="dashed", linewidth=1)
    plt.text(median_val * 1.0, max_ylim * 0.9, f"Median: {median_val:.2f} ({median_ctid})")
    plt.axvline(min_val, color="k", linestyle="dashed", linewidth=1)
    plt.text(min_val * 1.0, max_ylim * 0.9, f"Min: {min_val:.2f} ({min_ctid})")

    # scaling and labeling
    # ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Percent of Unique IPs Flagged as Bots")
    ax.set_ylabel("Number of Domains")
    ax.set_title("Percent of Unique IPs Flagged as Bots per Domain")
    plot_utils.style_grid(ax, ticks=True)
    plt.tight_layout()

    plot_file = PLOT_DIR / "hist_filtered.png"
    plt.savefig(plot_file, facecolor="white")
    plt.close(fig)

    LOGGER.info(f"Finished plot_hist_filtered...")


def plot_cdf_filtered(idx_ptrn, results_file):

    # LOGGER.info(f"plot_cdf_filtered {idx_ptrn} {results_file}...")
    df = get_tag_ctr_status_df(results_file)
    df = aggregate_blocklist_cols(df)

    bot_col_name = "bot_percent"
    user_col_name = "user_percent"
    funcs = {
        user_col_name: lambda x: (x.user) / (x.bot + x.both + x.user + x.untagged),
        bot_col_name: lambda x: (x.bot + x.both) / (x.bot + x.both + x.user + x.untagged),
    }
    for col_name, _func in funcs.items():
        df[col_name] = df.apply(_func, axis=1)
    df = df.dropna()
    df = df.sort_values(by=[bot_col_name, user_col_name], ascending=[True, False])

    fig, ax = plt.subplots(1, 1, figsize=(6, 3))
    labels = ["Residual Trust CDF", "Bot CDF"]
    stats_dfs = {}
    for idx, col_name in enumerate(funcs):
        stats_df = (
            df.groupby(col_name)[col_name]
            .agg("count")
            .pipe(pd.DataFrame)
            .rename(columns={col_name: "freq"})
        )
        stats_df["pdf"] = stats_df["freq"] / sum(stats_df["freq"])
        stats_df["cdf"] = stats_df["pdf"].cumsum()
        stats_df = stats_df.reset_index()
        stats_df[col_name] = stats_df[col_name]
        stats_dfs[col_name] = stats_df
        # ax.plot(stats_df[col_name], stats_df.pdf, label=f"{label_prefix[idx]} pdf")
        ax.plot(stats_df[col_name], stats_df.cdf, label=labels[idx])

    annotate = {user_col_name: 0.01, bot_col_name: 0.95}
    xytexts = {user_col_name: (30, -30), bot_col_name: (-60, 30)}
    for col_name, val in annotate.items():
        # ax.axvline(val, color="k", linestyle="dashed", linewidth=1)
        stats_df = stats_dfs[col_name]
        num_domains = stats_df[stats_df[col_name] < val].shape[0]
        percentage = num_domains / stats_df.shape[0]
        text = f"({val},{percentage:.2f})"
        xytext = xytexts[col_name]
        ax.annotate(
            text,
            xy=(val, percentage),
            xytext=xytext,
            textcoords="offset points",
            # ha="right",
            # va="center",
            bbox=dict(boxstyle="round", alpha=0.1),
            arrowprops=dict(arrowstyle="wedge,tail_width=0.5", alpha=0.1),
        )
    ax.grid(True)
    ax.set_ylabel(f"Percentage of Domains (N={df.shape[0]})")
    ax.set_xlabel("Percentage of Unique IPs Seen for Each Domain")
    # ax.set_title("Filtering Results per Domain")
    ax.legend()
    plot_file = PLOT_DIR / "cdf_filtered.png"
    plt.tight_layout()
    plt.savefig(plot_file, facecolor="white")
    plt.clf()


###############################################################################


def get_service_status(idx_ptrn, results_file):
    ip_idx = es_utils.get_geoip_index(idx_ptrn)
    search = es_utils.init_query(
        QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None, sort_timestamp=False
    ).params(size=1_000)
    num_bot_tagged = defaultdict(int)
    untagged = 0
    user_tagged = 0
    LOGGER.info(f"get_service_status for {idx_ptrn} {results_file}")
    for idx, hit in enumerate(search.scan()):
        if idx % LOG_PROGRESS[idx_ptrn] == 0:
            LOGGER.debug(f"  on {idx}")
        if es_utils.ip_tagged_bot(hit):
            num_bot_tags = len(hit.bot_filter_tags)
            num_bot_tagged[num_bot_tags] += 1
        elif es_utils.ip_tagged_user(hit):
            user_tagged += 1
        else:
            untagged += 1
    bot_tagged = sum(num_bot_tagged.values())
    total = bot_tagged + untagged + user_tagged
    results = dict(
        idx_ptrn=idx_ptrn,
        bot_tagged=bot_tagged,
        untagged=untagged,
        user_tagged=user_tagged,
        total=total,
        num_bot_tagged=num_bot_tagged,
    )
    with open(results_file, "a+") as f:
        out = f"{json.dumps(results)}\n"
        f.write(out)


def load_service_status(status_file):
    return load_status(status_file, "idx_ptrn")


def plot_service_status(idx_ptrns, status_file):
    LOGGER.info(f"plot_service_status {idx_ptrns} {status_file}")
    status = load_service_status(status_file)
    cols = ["idx_ptrn", "not_bots", "bots"]
    rows = []
    for idx_ptrn in idx_ptrns:
        if idx_ptrn not in status:
            continue
        o = status[idx_ptrn]
        not_bots = o["untagged"] + o["user_tagged"]
        bots = o["bot_tagged"]
        row = [idx_ptrn, not_bots, bots]
        rows.append(row)
    df = pd.DataFrame(rows, columns=cols)
    fig, ax = plt.subplots(nrows=1, ncols=1)
    labels = [IDX_PTRN_TO_SERVICE[ptrn] for ptrn in df.idx_ptrn]
    width = 0.35
    x = np.arange(len(labels))
    ax.bar(x - width / 2, df.bots, width, label="Bots")
    ax.bar(x + width / 2, df.not_bots, width, label="Non-Bots")
    ax.set_ylabel("Number of IPs")
    ax.set_title("Number of IPs Flagged as Bots by Service")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_yscale("log")
    ax.legend()
    fig.tight_layout()
    plot_utils.style_grid(ax)
    plt.savefig(PLOT_DIR / "service_status.png", facecolor="white")


###############################################################################


def get_untagged_ips_ctrs(idx_ptrn, results_file):
    ip_idx = es_utils.get_geoip_index(idx_ptrn)
    search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=None, ctids=None).params(
        size=1000
    )
    LOGGER.info(f"get_untagged_ips_ctrs {idx_ptrn}")
    ctr_num_ips = defaultdict(int)
    for idx, hit in enumerate(search.scan()):
        if idx % LOG_PROGRESS[idx_ptrn] == 0:
            LOGGER.debug(f"  on ip {idx}")
        ip = hit.ip
        if es_utils.ip_tagged_bot(hit):
            continue
        idx_search = es_utils.init_query(
            QueryEnum.SEARCH, ip_idx, filter_time=None, ctids=NONPLACEBO_IDS
        )
        idx_search = idx_search.query("term", **{es_utils.get_ip_field(idx_ptrn): ip})
        ctr_agg = {"ctr": A("terms", field="log.container.keyword")}
        _generator = es_utils.scan_aggs(idx_search, [ctr_agg], size=1000)
        for bucket in _generator:
            ctr = bucket.key.ctr
            ctr_num_ips[ctr] += 1
    with open(results_file, "a+") as f:
        out = f"{json.dumps(ctr_num_ips)}\n"
        f.write(out)


###############################################################################

# FUNCS = [get_containers_status, plot_containers_status, plot_hist_filtered]
FUNCS = [plot_cdf_filtered]


def analyze(idx_ptrn, results_file):
    for func in FUNCS:
        func(idx_ptrn, results_file)