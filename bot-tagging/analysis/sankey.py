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
from elasticsearch_dsl import A, Q

# proj
from enums import QueryEnum, TagEnum
from services import nginx, ftp_telnet, ssh
import utils
import es_utils
import plot_utils


###############################################################################

LOGGER = utils.get_logger("analysis")
NONPLACEBOS = utils.get_nonplacebos()
NONPLACEBO_IDS = [str(_id) for _id in NONPLACEBOS]

LOG_PROGRESS = {"nginx-access-*": 100_000, "ftp-*": 1_000, "telnet-*": 10_000, "ssh-*": 10_000}

IDX_PTRN_SERVICES = {
    "nginx-access-*": nginx,
    "ftp-*": ftp_telnet,
    "telnet-*": ftp_telnet,
    "ssh-*": ssh,
}
SRVC_NAMES = {
    "nginx-access-*": "web",
    "ftp-*": "ftp",
    "telnet-*": "telnet",
    "ssh-*": "ssh",
}
PLOT_DIR = Path("plots/sankey")
PLOT_DIR.mkdir(parents=True, exist_ok=True)

BOT_TAG_GROUPING = {
    "placebo": ["placebo-ip", "other-placebo-ip"],
    "other-service-bot-ip": ["other-service-bot-ip"],
    "mirai": ["mirai"],
    "dnsbl": ["blocklist"],
    "firehol-blocklist": ["bl"],
    "bot-path": [
        "bot-trap",
        "init-setup",
        "shell",
        "logins",
        "proxy",
        "path-traversal",
        "bot-endpoints",
        "additional-be",
    ],
    "fingerprint": ["web-fingerprint", "ua-fp_exists", "ua-bot"],
}
USER_TAG_GROUPING = {"residual-path": ["residual-path"], "fingerprint": ["ua-fp_exists"]}

###############################################################################


def get_tag_filter_stats(idx_ptrn):
    def _verify_tag_grouping(tags, grouping):
        for tag in tags:
            groups = []
            for (group, group_tags) in grouping.items():
                if tag in group_tags:
                    groups.append(group)
                    break
            assert len(groups) == 1, f"tag={tag} groups={groups}"

    def _verify_numbers(total_ips, bot_tags_status, user_tags_status, untagged_ips):
        _sum = sum(bot_tags_status.values()) + sum(user_tags_status.values()) + untagged_ips
        msg = f"numbers do not add up, sum={_sum}, total_ips={total_ips}"
        assert total_ips - _sum == 0, msg

    def _get_unique_case_ips(idx_ptrn, ctid, bot_grouping, user_grouping):
        unique_ctid_ips = es_utils.get_unique_ctid_ips(idx_ptrn, ctid)
        bot_case_tags = defaultdict(int)
        user_case_tags = defaultdict(int)
        untagged_case_ips = 0
        for ip in unique_ctid_ips:
            tag_status, tag_group = es_utils.get_ip_tag_group(
                idx_ptrn, ip, bot_grouping, user_grouping
            )
            if tag_status == TagEnum.BOT:
                bot_case_tags[tag_group] += 1
            elif tag_status == TagEnum.USER:
                user_case_tags[tag_group] += 1
            else:
                untagged_case_ips += 1
        total_case_ips = (
            sum(bot_case_tags.values()) + sum(user_case_tags.values()) + untagged_case_ips
        )
        return bot_case_tags, user_case_tags, untagged_case_ips, total_case_ips

    def _get_total_ips(idx_ptrn):
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None)
        return search.count()

    def _get_untagged_ips(idx_ptrn):
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None)
        untagged_q = Q(
            "bool",
            must_not=[
                Q("exists", field=es_utils.BOT_TAGS_FIELD),
                Q("exists", field=es_utils.USER_TAGS_FIELD),
            ],
        )
        search = search.query(untagged_q)
        return search.count()

    def _get_ips_for_tags(idx_ptrn, tags, exclude, bot):
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None)
        main_field = es_utils.BOT_TAGS_FIELD if bot else es_utils.USER_TAGS_FIELD
        other_field = es_utils.USER_TAGS_FIELD if bot else es_utils.BOT_TAGS_FIELD
        main_field = f"{main_field}.keyword"
        other_field = f"{other_field}.keyword"
        should = [Q("wildcard", **{main_field: {"value": f"{tag}*"}}) for tag in tags]
        must_not = [Q("wildcard", **{main_field: {"value": f"{e_tag}*"}}) for e_tag in exclude]
        if not bot:
            must_not.append(Q("exists", field=other_field))
        tag_q = Q("bool", must_not=must_not, should=should, minimum_should_match=1)
        search = search.query(tag_q)
        return search.count()

    def _get_tags_status_helper(idx_ptrn, grouping, bot):
        grouping_keys = list(grouping.keys())
        for i in range(len(grouping_keys)):
            g_tag = grouping_keys[i]
            excluded_groups = grouping_keys[:i]
            e_tags = [e_tag for e_grp in excluded_groups for e_tag in grouping[e_grp]]
            LOGGER.debug(f"    getting status for group tag={g_tag}")
            num_ips = _get_ips_for_tags(idx_ptrn, grouping[g_tag], e_tags, bot)
            yield {g_tag: num_ips}

    def _get_tags_status(idx_ptrn, grouping, bot):
        LOGGER.info(f"  _get_tags_status bot={bot} grouping={grouping}")
        tags_status = {}
        for delta in _get_tags_status_helper(idx_ptrn, grouping, bot):
            tags_status.update(delta)
        LOGGER.info(f"  got tags status {tags_status}")
        return tags_status

    def _get_node_pos(bot_tags_status, user_tags_status, case_labels):
        bot_labels = list(bot_tags_status.keys())
        user_labels = list(user_tags_status.keys())
        ncols = 3 if len(case_labels) == 0 else 4
        x_bot_start = 1.0 if ncols == 3 else 0.67
        x_user_start = 1.0 if ncols == 3 else 0.67
        y_bot_start = 0.1
        y_user_start = 0.6
        x_status_label_group = 1.0 / (ncols - 1)
        sum_bot = sum(bot_tags_status.values())
        sum_user = sum(user_tags_status.values())
        bot_tick_step = (y_user_start - y_bot_start) / sum_bot
        user_tick_step = (1 - y_user_start) / sum_user
        bot_label_pos = []
        user_label_pos = []
        case_label_pos = [i / len(case_labels) for i in range(len(case_labels))]
        # pdb.set_trace()
        for idx, label in enumerate(bot_labels):
            curr_num = bot_tags_status[label]
            if idx > 0:
                prev_labels = bot_labels[:idx]
                y = sum([bot_tags_status[label] for label in prev_labels])
                y = y_bot_start + (y * bot_tick_step)
                # y = y_bot_start + ((y + curr_num / 2) * bot_tick_step)
            else:
                y = y_bot_start
                # y = y_bot_start + ((curr_num / 2) * bot_tick_step)
            bot_label_pos.append((x_bot_start, y))
        for idx, _ in enumerate(user_labels):
            curr_num = user_tags_status[label]
            if idx > 0:
                prev_labels = user_labels[:idx]
                y = sum([user_tags_status[label] for label in prev_labels])
                y = y_user_start + (y * user_tick_step)
                # y = y_user_start + ((y + curr_num / 2) * user_tick_step)
            else:
                y = y_user_start
                # y = y_user_start + ((curr_num / 2) * user_tick_step)
            user_label_pos.append((x_user_start, y))

        # bot_multiplier = (y_user_start - y_bot_start) / len(bot_tags)
        # user_multiplier = (1 - y_user_start) / len(user_tags)
        node_pos = [
            (0.0, 0.3),
            (x_status_label_group, 0.1),
            *bot_label_pos,
            (x_status_label_group, 0.6),
            *user_label_pos,
            (x_status_label_group, 1.0),
            *case_label_pos,
        ]
        return node_pos

    def _get_sankey_data(
        bot_tags_status,
        user_tags_status,
        untagged_ips,
        total_ips,
        original_case_tags=dict(),
        scale=lambda x: x,
    ):
        # need to remove 0s otherwise positioning messes up
        bot_tags_status = {k: scale(v) for k, v in bot_tags_status.items() if v > 0}
        user_tags_status = {k: scale(v) for k, v in user_tags_status.items() if v > 0}
        case_labels = list(original_case_tags.keys())
        case_tags = {}
        for ctid, (ctid_bot, ctid_user, ctid_untagged, ctid_total) in case_tags:
            new_ctid_bot = {k: scale(v) for k, v in ctid_bot.items() if v > 0}
            new_ctid_user = {k: scale(v) for k, v in ctid_user.items() if v > 0}
            new_ctid_untagged = scale(ctid_untagged)
            new_ctid_total = scale(ctid_total)
            case_tags[ctid] = (new_ctid_bot, new_ctid_user, new_ctid_untagged, new_ctid_total)
        untagged_ips = scale(untagged_ips)
        total_ips = scale(total_ips)
        data_tuples = []
        bot_labels = list(bot_tags_status.keys())
        user_labels = list(user_tags_status.keys())
        node_labels = ["init", "bot", *bot_labels, "user", *user_labels, "neutral", *case_labels]
        init_node = 0  # alternatively, use .index
        bot_node = 1
        user_node = len(bot_tags_status) + 2
        neutral_node = len(node_labels) - 1 - len(case_labels)

        node_pos = _get_node_pos(bot_tags_status, user_tags_status, case_labels)
        sum_bot = sum(bot_tags_status.values())
        sum_user = sum(user_tags_status.values())
        node_label_nums = []
        node_label_nums.append(total_ips)
        node_label_nums.append(sum_bot)
        node_label_nums.extend([v for _, v in bot_tags_status.items()])
        node_label_nums.append(sum_user)
        node_label_nums.extend([v for _, v in user_tags_status.items()])
        node_label_nums.append(untagged_ips)
        node_label_nums.extend([case_tags[ctid][3] for ctid in case_labels])
        node_labels = [
            f"{label} ({node_label_nums[idx]:,})" for idx, label in enumerate(node_labels)
        ]

        data_tuples.append((init_node, bot_node, sum_bot))
        data_tuples.append((init_node, user_node, sum_user))
        data_tuples.append((init_node, neutral_node, untagged_ips))
        for idx, (_, num_ips) in enumerate(bot_tags_status.items()):
            bot_tag_node = bot_node + idx + 1
            data_tuples.append((bot_node, bot_tag_node, num_ips))
        for idx, (_, num_ips) in enumerate(user_tags_status.items()):
            user_tag_node = user_node + idx + 1
            data_tuples.append((user_node, user_tag_node, num_ips))
        for (ctid, (bot_ctid, user_ctid, untagged_ctid, _)) in case_tags.items():
            ctid_node = case_labels.index(ctid) + 4 + len(bot_labels) + len(user_labels)
            for bot_ctid_tag, bot_ctid_tag_num in bot_ctid.items():
                src_node = bot_labels.index(bot_ctid_tag) + 2
                data_tuples.append((src_node, ctid_node, bot_ctid_tag_num))
            for user_ctid_tag, user_ctid_tag_num in user_ctid.items():
                src_node = user_labels.index(user_ctid_tag) + 3 + len(bot_labels)
                data_tuples.append((src_node, ctid_node, user_ctid_tag_num))
            data_tuples.append((neutral_node, ctid_node, untagged_ctid))
        return node_labels, data_tuples, node_pos

    srvc = IDX_PTRN_SERVICES[idx_ptrn]
    bot_tags = list(srvc.BOT_TAG_PIPELINE.keys())
    user_tags = list(srvc.USER_TAG_PIPELINE.keys())
    _verify_tag_grouping(bot_tags, BOT_TAG_GROUPING)
    _verify_tag_grouping(user_tags, USER_TAG_GROUPING)
    total_ips = _get_total_ips(idx_ptrn)
    untagged_ips = _get_untagged_ips(idx_ptrn)
    bot_tags_status = _get_tags_status(idx_ptrn, BOT_TAG_GROUPING, True)
    user_tags_status = _get_tags_status(idx_ptrn, USER_TAG_GROUPING, False)
    _verify_numbers(total_ips, bot_tags_status, user_tags_status, untagged_ips)

    # pdb.set_trace()
    # cases = [657, 837, 710, 833]
    # cases = [837]
    # case_tags = {
    #     str(ctid): _get_unique_case_ips(idx_ptrn, str(ctid), BOT_TAG_GROUPING, USER_TAG_GROUPING)
    #     for ctid in cases
    # }
    sankey_labels, sankey_data, sankey_pos = _get_sankey_data(
        bot_tags_status,
        user_tags_status,
        untagged_ips,
        total_ips,
        # original_case_tags=case_tags,
        scale=lambda x: x,
    )
    srvc_name = SRVC_NAMES[idx_ptrn]
    plot_file = PLOT_DIR / f"sankey-{srvc_name}.html"
    sankey = plot_utils.plot_sankey(
        sankey_labels,
        sankey_data,
        plot_file,
        pos=sankey_pos,
        title=f"Filtering Level Effects on Unique Client IPs for {srvc_name}",
    )
    LOGGER.info(f"plotted sankey for {idx_ptrn}: {plot_file}")


###############################################################################

# FUNCS = [get_asn_distribution, get_top_n_asn_placebos, get_top_n_asn_nonplacebos]
FUNCS = [get_tag_filter_stats]


def analyze(idx_ptrn):
    for func in FUNCS:
        func(idx_ptrn)
