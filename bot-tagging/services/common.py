# stdlib
import concurrent.futures as cfutures
from datetime import datetime, timedelta
import glob
import gzip
from ipaddress import IPv4Address, IPv4Network, AddressValueError
from pathlib import Path
import socket
import pdb

# 3p
from elasticsearch_dsl import Q, A
from pydnsbl import DNSBLIpChecker

# proj
from enums import QueryEnum, TagEnum
import es_utils
import utils


###############################################################################

CONFIG = utils.get_config()
LOGGER = utils.get_logger("services_common")

PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

PLACEBO_IDS = [str(_id) for _id in sorted(list(PLACEBOS.keys()))]
NONPLACEBO_IDS = [str(_id) for _id in sorted(list(NONPLACEBOS.keys()))]
LOG_PROGRESS = {"nginx-access-*": 100_000, "telnet-*": 10_000, "ssh-*": 10_000, "ftp-*": 1_000}
ALL_IDX_PTRNS = ["nginx-access-*", "ftp-*", "telnet-*", "ssh-*"]

BATCH_SIZE = 1024
NUM_WORKERS = 4
BLOCKLIST_DATA_DIR = Path(CONFIG["BLOCKLIST_IPSETS_DIR"])
FINGERPRINTS_IDX_PTRN = "fp-*"
BLOCKLIST_IPSETS = None

DOMAIN_BOT_INDICATORS = ["google", "bing", "bot", "crawl"]

###############################################################################


def get_blocklist_ips():
    blocklist_filenames = utils.get_blocklists()
    blocklist_filenames = [BLOCKLIST_DATA_DIR / filename for filename in blocklist_filenames]
    blocklist_ipsets = {}
    for filepath in blocklist_filenames:
        files = glob.iglob(str(filepath))
        for f in files:
            ips = set()
            f_path = Path(f)
            lines = utils._get_lines(f)
            for line in lines:
                try:
                    addr = IPv4Address(line)
                    ips.add(addr)
                except AddressValueError:
                    pass
                try:
                    subnet = IPv4Network(line)
                    ips.add(subnet)
                except AddressValueError:
                    pass
            key = f_path.name[: f_path.name.index(".")]
            blocklist_ipsets[key] = ips
    return blocklist_ipsets


###############################################################################
# COMMON


def tag_idx_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in the index pattern's placebo traffic. """
    indices = [idx_ptrn]
    return tag_placebo_ips(tag, idx_ptrn, indices, search_only=search_only)


def tag_other_placebo_ips(tag, idx_ptrn, search_only=False):
    """ Tag all documents in idx_ptrn whose client IP was found in other placebo traffic. """
    indices = [ptrn for ptrn in ALL_IDX_PTRNS if ptrn != idx_ptrn]
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


def tag_mirai_ips(tag, idx_ptrn, search_only=False):
    if search_only:
        raise NotImplementedError()
    ips = utils.get_mirai_ips()
    es_utils.tag_ips(idx_ptrn, ips, tag, bucketed=False)
    return []


def tag_other_services_bot_ips(tag, idx_ptrn, search_only=False):
    def _yield_bot_ips(idx_ptrn):
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
        for idx, hit in enumerate(search.scan()):
            if idx % LOG_PROGRESS[idx_ptrn] == 0:
                LOGGER.debug(f"  on ip {idx}...")
            if es_utils.ip_tagged_bot(hit):
                yield hit.ip

    if search_only:
        raise NotImplementedError()
    indices = [ptrn for ptrn in ALL_IDX_PTRNS if ptrn != idx_ptrn]
    for other_idx in indices:
        LOGGER.info(f"tag_other_services_bot_ips idx_ptrn={idx_ptrn} other_idx={other_idx}")
        other_bot_ips = _yield_bot_ips(other_idx)
        es_utils.tag_ips(idx_ptrn, other_bot_ips, tag, bucketed=False)
    return []


def tag_blocklist_ips(tag, idx_ptrn, search_only=False):
    def _yield_ips(idx_ptrn):
        ip_idx = es_utils.get_geoip_index(idx_ptrn)
        search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False)
        for hit in search.scan():
            if es_utils.ip_tagged_bot(hit):
                continue
            yield hit.ip

    def _process_ip(ip):
        ip_checker = DNSBLIpChecker()
        res = ip_checker.check(ip)
        return res

    def _yield_blocklisted_ips(ips_gen):
        ips = utils.batch_iterable(ips_gen, n=BATCH_SIZE)
        num_ips = 0
        start_time = datetime.now()
        log_every_nth_batch = 50
        with cfutures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            for idx, batch_ips in enumerate(ips):
                # if (idx * BATCH_SIZE) < 358_400:
                #     continue
                if idx % log_every_nth_batch == 0:
                    LOGGER.debug(f"  on ip {idx*BATCH_SIZE} ({datetime.now() - start_time})")
                future_to_ip = {executor.submit(_process_ip, ip): ip for ip in batch_ips}
                for future in cfutures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        res = future.result()
                        if res.blacklisted:
                            if num_ips % (log_every_nth_batch * BATCH_SIZE) == 0:
                                LOGGER.debug(
                                    f"  detected {num_ips} ({datetime.now() - start_time})"
                                )
                            num_ips += 1
                            yield ip
                    except Exception as e:
                        LOGGER.warning(f"err with future.result {ip}: {e}")
        LOGGER.info(f"detected {num_ips} in {datetime.now() - start_time}")

    if search_only:
        raise NotImplementedError()
    LOGGER.info(f"tag_blocklist_ips idx_ptrn={idx_ptrn}")
    ips_gen = _yield_ips(idx_ptrn)
    blocklisted_ips_gen = _yield_blocklisted_ips(ips_gen)
    es_utils.tag_ips(idx_ptrn, blocklisted_ips_gen, tag, bucketed=False)
    return []


def tag_blocklist_ipsets(tag, idx_ptrn, search_only=False):
    # def _get_bl_ips(tag, ipsets):
    #     for blist, ips in ipsets.items():
    #         if blist not in tag:
    #             continue
    #         for _ip in ips:
    #             yield str(_ip)

    def _get_bl_ips(ips):
        for ip in ips:
            yield str(ip)

    if search_only:
        raise NotImplementedError()

    global BLOCKLIST_IPSETS
    LOGGER.info(f"tag_blocklist_ipsets tag={tag} idx_ptrn={idx_ptrn}")
    if BLOCKLIST_IPSETS is None:
        BLOCKLIST_IPSETS = get_blocklist_ips()
    for idx, (blist, ips) in enumerate(BLOCKLIST_IPSETS.items()):
        if idx % 10 == 0:
            LOGGER.debug(f"  blist {idx} {blist} {len(ips)} items...")
        ips_gen = _get_bl_ips(ips)
        bl_tag = f"{tag}_{blist}"
        es_utils.tag_ips(idx_ptrn, ips_gen, bl_tag, bucketed=False)
    return []


def tag_web_fingerprints(tag, idx_ptrn, search_only=False):
    def _get_ip_from_fp(hit):
        ip = None
        keys = ["geobytesipaddress", "geobytesremoteip", "ip"]
        for key in keys:
            try:
                ip = hit.fp.clientIP[key]
                break
            except KeyError:
                pass
        if ip is None:
            LOGGER.warning(f"  no ip for fp id {hit.meta.id}")
        return ip

    def _fp_is_botlike(hit, bot_indicators):
        ip = _get_ip_from_fp(hit)
        is_botlike = not ("user_agent" in hit.fp)
        if "user_agent" in hit.fp:
            is_botlike = is_botlike or "bot" in hit.fp.user_agent
        if not is_botlike:
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                names = [hostname, *aliases]
                for name in names:
                    for indicator in bot_indicators:
                        is_botlike = is_botlike or indicator in name
            except socket.herror:
                LOGGER.debug(f"    unknown host for ip {ip}")
        return is_botlike

    def _yield_fingerprint_ips(bot=True):
        search = es_utils.init_query(QueryEnum.SEARCH, FINGERPRINTS_IDX_PTRN, filter_time=True)
        search = search.params(size=1_000)
        for idx, hit in enumerate(search.scan()):
            if idx % 100_000 == 0:
                LOGGER.debug(f"  bot fingerprint doc {idx}...")
            ip = _get_ip_from_fp(hit)
            is_botlike = _fp_is_botlike(hit, bot_indicators=DOMAIN_BOT_INDICATORS)
            _yield = bot == is_botlike  # biconditional
            if _yield:
                yield ip

    if search_only:
        raise NotImplementedError()
    LOGGER.info(f"tag_web_fingerprints idx_ptrn={idx_ptrn}")

    # bots
    bot_ips_gen = _yield_fingerprint_ips(bot=True)
    es_utils.tag_ips(idx_ptrn, bot_ips_gen, tag, bucketed=False)

    # users
    # user_ips_gen = _yield_fingerprint_ips(bot=False)
    # es_utils.tag_ips(idx_ptrn, user_ips_gen, tag, bot=False, bucketed=False)
    return []


def tag(tags, idx_ptrn, pipelines, init=False, placebo=False):
    if init:
        es_utils.init_ip_index(idx_ptrn, placebo=placebo)
    LOGGER.info(f">> {idx_ptrn} placebo={placebo} pipelines for {tags}")
    pipelines_start = datetime.now()
    for pipeline in pipelines:
        for tag in tags:
            if tag not in tags or tag not in pipeline:
                continue
            func = pipeline[tag]
            LOGGER.info(f"{idx_ptrn} tagging: {tag}, {func.__name__}")
            start_time = datetime.now()
            func(tag, idx_ptrn, placebo)
            elapsed = datetime.now() - start_time
            LOGGER.info(f"{tag}, {func.__name__} completed in {elapsed}")
    elapsed = datetime.now() - pipelines_start
    LOGGER.info(f">> {idx_ptrn} pipelines completed in {elapsed}")


def scan(tags, idx_ptrn, pipelines, aggs, init_data, process_bucket, process_data):
    LOGGER.info(f">> {idx_ptrn} scanning {tags}")
    pipeline_start = datetime.now()
    for pipeline in pipelines:
        for tag in tags:
            if tag not in tags:
                continue
            func = pipeline[tag]
            LOGGER.info(f"{idx_ptrn} scanning: {tag}, {func.__name__}")
            data = init_data(tag, idx_ptrn)
            start_time = datetime.now()
            tag_searches = func(tag, idx_ptrn, search_only=True)
            for s_idx, search in enumerate(tag_searches):
                LOGGER.info(f"  search {s_idx}/{len(tag_searches)}: {search.to_dict()}")
                buckets = es_utils.scan_aggs(search, aggs)
                for idx, bucket in enumerate(buckets):
                    if idx % LOG_PROGRESS[idx_ptrn] == 0:
                        LOGGER.info(f"  {idx_ptrn} scan {s_idx} on bucket {idx}...")
                    process_bucket(data, bucket)
            elapsed = datetime.now() - start_time
            LOGGER.info(f"yielded after {elapsed.total_seconds()} seconds")
            yield process_data(data)
    elapsed = datetime.now() - pipeline_start
    LOGGER.info(f">> {idx_ptrn} scanning completed in {elapsed.total_seconds()}")


###############################################################################
# CREDENTIALS

## CONSTANTS

FTP_IDX_PTRN = "ftp-*"
TELNET_IDX_PTRN = "telnet-*"
SSH_IDX_PTRN = "ssh-*"
USER_FIELD_MAP = {
    FTP_IDX_PTRN: "ftp.user",
    TELNET_IDX_PTRN: "telnet.user",
    SSH_IDX_PTRN: "ssh.username",
}
PASS_FIELD_MAP = {
    FTP_IDX_PTRN: "ftp.password",
    TELNET_IDX_PTRN: "telnet.password",
    SSH_IDX_PTRN: "ssh.password",
}

ROCKYOU_FILE = "/mnt/analysis_artifacts/rt_expired/rockyou.txt.gz"
MOST_COMMON_ROCKYOU = 1_000

FMT_ISO_TIME = "%Y-%m-%dT%H:%M:%SZ"

EDIT_DIST_ROCKYOU = 2
EDIT_DIST_REPEATED = 1
SESSION_DUR_MINS = 1

## HELPERS


def get_user_field(idx_ptrn, keyword=True):
    val = USER_FIELD_MAP[idx_ptrn]
    if keyword:
        val = f"{val}.keyword"
    return val


def get_pass_field(idx_ptrn, keyword=True):
    val = PASS_FIELD_MAP[idx_ptrn]
    if keyword:
        val = f"{val}.keyword"
    return val


def get_rockyou_passwords():
    with gzip.open(ROCKYOU_FILE, "r") as f:
        lines = []
        for line in f:
            if len(lines) >= MOST_COMMON_ROCKYOU:
                break
            try:
                lines.append(line.rstrip().decode())
            except UnicodeDecodeError as e:
                # print(f"{idx} {line} {e}")
                pass
        LOGGER.info(f"Loaded the top {len(lines)} ROCKYOU passwords.")
        return set(lines)


def get_placebo_creds(idx_ptrn):
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=False, ctids=PLACEBO_IDS, sort_timestamp=False
    )
    user_agg = {"user": A("terms", field=get_user_field(idx_ptrn))}
    pass_agg = {"pwd": A("terms", field=get_pass_field(idx_ptrn))}
    creds_gen = es_utils.scan_aggs(search, [user_agg, pass_agg])
    return creds_gen


## BASE TAGGERS


def _tag_by_creds(
    tag,
    idx_ptrn,
    creds,
    ctids=NONPLACEBO_IDS,
    query_type="term",
    keyword=True,
    prefix_wild=False,
    search_only=False,
):
    """
    Parameters
    ----------
    creds : [(user,password)]
    """

    def _get_should(idx_ptrn, query_type, cred, keyword, prefix_wild):
        user, pwd = cred
        user_field = get_user_field(idx_ptrn, keyword=keyword)
        pass_field = get_pass_field(idx_ptrn, keyword=keyword)
        if query_type == "wildcard":
            user = f"{user}*" if not prefix_wild else f"*{user}*"
            pwd = f"{pwd}*" if not prefix_wild else f"*{pwd}*"
        if user is not None and len(user) > 0:
            should = Q(query_type, **{user_field: user}) & Q(query_type, **{pass_field: pwd})
        else:
            should = Q(query_type, **{pass_field: pwd})
        return should

    LOGGER.info(f"Tagging {tag} for {creds[:10]}...")
    search = es_utils.init_query(
        QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=ctids, sort_timestamp=False
    )
    must = []
    must_nots = []
    query = Q(
        "bool",
        must=must,
        must_not=must_nots,
        should=[_get_should(idx_ptrn, query_type, cred, keyword, prefix_wild) for cred in creds],
        minimum_should_match=1,
    )
    search = search.query(query)
    if not search_only:
        ips_gen = es_utils.get_ips(idx_ptrn, search=search)
        es_utils.tag_ips(idx_ptrn, ips_gen, tag)
    return search


def _tag_rockyou_passwords(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose password is in the top N rockyou password leak. """
    rockyou_passwords = get_rockyou_passwords()
    LOGGER.info(f"_tag_rockyou_passwords idx_ptrn={idx_ptrn}")
    creds = [(None, pwd) for pwd in rockyou_passwords]
    return [_tag_by_creds(tag, idx_ptrn, creds, search_only=search_only)]


def _get_common_domain_pwds(domain):
    dot_idx = domain.rfind(".")
    hyphenated = domain[:dot_idx] + "-" + domain[dot_idx + 1 :]
    underscored = domain[:dot_idx] + "_" + domain[dot_idx + 1 :]
    no_gap = domain[:dot_idx] + domain[dot_idx + 1 :]
    no_tld = domain[:dot_idx]
    common = [domain, hyphenated, underscored, no_gap, no_tld]
    return common


def _tag_domain_passwords(tag, idx_ptrn, search_only=False):
    """ Tag all documents whose password contains the domain of the container. """
    LOGGER.info(f"_tag_domain_passwords idx_ptrn={idx_ptrn}")
    searches = []
    for idx, (ctid, ctr_info) in enumerate(NONPLACEBOS.items()):
        ctr = str(ctid)
        if idx % 10 == 0:
            LOGGER.info(f"  on ctr {ctr} of {len(NONPLACEBOS)}")
        domain = ctr_info["domain"]
        pwds = _get_common_domain_pwds(domain)
        creds = [(None, pwd) for pwd in pwds]
        search = _tag_by_creds(
            tag,
            idx_ptrn,
            creds,
            ctids=[ctr],
            query_type="wildcard",
            keyword=True,
            prefix_wild=True,
            search_only=search_only,
        )
        searches.append(search)
    return searches


def _tag_placebo_credentials(tag, idx_ptrn, search_only=False):
    """ Tag all documents who have a (user,password) pair that can be found in placebos. """

    def _extract_user_pass(creds_gen, n=100):
        batch = []
        for bucket in creds_gen:
            if len(batch) == n:
                yield batch
                batch = []
            user = bucket.key.user
            pwd = bucket.key.pwd
            batch.append((user, pwd))
        if len(batch) > 0:
            yield batch

    searches = []
    creds_gen = get_placebo_creds(idx_ptrn)
    creds_gen = _extract_user_pass(creds_gen)
    for idx, batch in enumerate(creds_gen):
        if idx % 1_000 == 0:
            LOGGER.info(f"  _tag_placebo_credentials at batch {idx}...")
        batch_search = _tag_by_creds(tag, idx_ptrn, batch, search_only=search_only)
        searches.append(batch_search)
    return searches


def _yield_repeated_creds_ips(tag, idx_ptrn, search_only=False):
    if search_only:
        raise NotImplementedError()

    import edit_distance

    def _pw_close_rockyou(rockyou, pw, distance=1):
        for _pw in rockyou:
            sm = edit_distance.SequenceMatcher(a=_pw, b=pw)
            if sm.distance() <= distance:
                return True
        return False

    def _pw_in_domain(ctid, pwd):
        domain = NONPLACEBOS[int(ctid)]["domain"]
        pwds = _get_common_domain_pwds(domain)
        retval = False
        for _pwd in pwds:
            retval = retval or pwd in _pwd or _pwd in pwd
        return retval

    def _get_fuzzy_query(timestamp, ctr, ip, user, pwd, distance):
        start_window = timestamp - timedelta(minutes=SESSION_DUR_MINS)
        end_window = timestamp + timedelta(minutes=SESSION_DUR_MINS)
        start_window = start_window.strftime(FMT_ISO_TIME)
        end_window = end_window.strftime(FMT_ISO_TIME)

        user_field = get_user_field(idx_ptrn, keyword=True)
        pass_field = get_pass_field(idx_ptrn, keyword=True)
        q = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=False, ctids=None)
        q = q.filter(
            "range",
            **{
                "@timestamp": {
                    "gte": start_window,
                    "lt": end_window,
                    "format": "date_time_no_millis",
                }
            },
        )
        q = q.query(
            "bool",
            must=[
                Q("term", **{es_utils.get_ip_field(idx_ptrn): {"value": ip}})
                & Q("term", log__container={"term": ctr})
            ],
            should=[
                Q(
                    "fuzzy",
                    **{user_field: {"value": user, "fuzziness": distance}},
                ),
                Q(
                    "fuzzy",
                    **{pass_field: {"value": pwd, "fuzziness": distance}},
                ),
            ],
            minimum_should_match=2,
        )
        return q

    ip_idx = es_utils.get_geoip_index(idx_ptrn)
    ip_search = es_utils.init_query(QueryEnum.SEARCH, ip_idx, filter_time=False, ctids=None).params(
        scroll="1h"
    )
    rockyou = get_rockyou_passwords()
    num_ips = 0
    srvc = idx_ptrn[: idx_ptrn.find("-")]
    LOGGER.info(f"_tag_repeated_creds {idx_ptrn}...")
    for idx_1, ip_hit in enumerate(ip_search.scan()):  # ip
        ip = ip_hit.ip
        if idx_1 % LOG_PROGRESS[idx_ptrn] == 0:
            LOGGER.debug(f"  on ip {idx_1} {ip}...")
        # if idx_1 <= 12553:  # catch up to last run
        #     continue
        search = es_utils.init_query(
            QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=NONPLACEBO_IDS
        ).query("term", ip=ip)
        ip_botlike = False
        for hit in search.scan():  # 1st hit
            timestamp = datetime.strptime(hit["@timestamp"], FMT_ISO_TIME)
            ctr = hit.log.container
            ip = hit.ip
            user = hit[srvc].user
            pwd = hit[srvc].password
            if _pw_in_domain(ctr, pwd) or _pw_close_rockyou(
                rockyou, pwd, distance=EDIT_DIST_ROCKYOU
            ):  # bot-like
                ip_botlike = True
                break
            fuzzy = _get_fuzzy_query(timestamp, ctr, ip, user, pwd, distance=EDIT_DIST_REPEATED)
            printed = False
            found_fuzzy = False
            for f_hit in fuzzy.scan():  # fuzzy hits
                if f_hit.meta.id == hit.meta.id:
                    continue
                if f_hit["@timestamp"] == hit["@timestamp"]:  # possible duplicate
                    continue
                f_user = f_hit[srvc].user
                f_pwd = f_hit[srvc].password
                if _pw_in_domain(ctr, f_pwd) or _pw_close_rockyou(
                    rockyou, f_pwd, distance=EDIT_DIST_ROCKYOU
                ):
                    ip_botlike = True
                    break
                if not printed:
                    if idx_1 % LOG_PROGRESS[idx_ptrn] != 0:
                        LOGGER.debug(f"  on ip {idx_1} {ip}")
                    LOGGER.debug(f"    hit {(user,pwd)}")
                    printed = True
                LOGGER.debug(f"      fuzzy {(f_user, f_pwd)}")
                found_fuzzy = True
            if ip_botlike:  # pw close to rockyou or domain
                break
            if found_fuzzy:
                if num_ips % 1_000 == 0:
                    LOGGER.info(f"  currently found {num_ips+1} ips...")
                num_ips += 1
                yield ip
                break  # don't need more fuzzy hits
    LOGGER.info(f"_tag_repeated_creds {idx_ptrn} found {num_ips} ips")

    # search = es_utils.init_query(QueryEnum.SEARCH, idx_ptrn, filter_time=True, ctids=None)
    # srvc = idx_ptrn[: idx_ptrn.find("-")]
    # rockyou = get_rockyou_passwords()
    # found_fuzzy_hits = set()
    # LOGGER.info(f"_tag_repeated_creds {idx_ptrn}...")
    # for idx, hit in enumerate(search.scan()):
    #     if idx % 10_000 == 0:
    #         LOGGER.debug(f"  _tag_repeated_creds on doc {idx}...")
    #     timestamp = datetime.strptime(hit["@timestamp"], FMT_ISO_TIME)
    #     ctr = hit.log.container
    #     ip = hit.ip
    #     user = hit[srvc].user
    #     pwd = hit[srvc].password
    #     if _pw_vs_rockyou(rockyou, pwd, distance=EDIT_DIST_ROCKYOU):
    #         continue
    #     if ip in found_fuzzy_hits:
    #         continue
    #     fuzzy = _get_fuzzy_query(timestamp, ctr, ip, user, pwd)
    #     printed = False
    #     found_fuzzy = False
    #     for fuzzy_hit in fuzzy.scan():
    #         if fuzzy_hit.meta.id == hit.meta.id:
    #             continue
    #         if fuzzy_hit["@timestamp"] == hit["@timestamp"]:  # possible duplicate
    #             continue
    #         if _pw_vs_rockyou(rockyou, fuzzy_hit[srvc].password, distance=EDIT_DIST_ROCKYOU):
    #             found_fuzzy = False
    #             break
    #         if not printed:
    #             print(f"hit {hit['@timestamp']} {hit.ip} {hit[srvc]}")
    #             printed = True
    #         print(f" fuzzy {fuzzy_hit['@timestamp']} {fuzzy_hit[srvc]}")
    #         found_fuzzy = True
    #     if found_fuzzy:
    #         print(f"found_fuzzy {hit.ip}")
    #         found_fuzzy_hits.add(hit.ip)
    # LOGGER.info(f"_tag_repeated_creds {idx_ptrn} {len(found_fuzzy_hits)} ips")
    # es_utils.tag_ips(idx_ptrn, found_fuzzy_hits, tag, bot=False, bucketed=False)


def _tag_repeated_credentials(tag, idx_ptrn, search_only=False):
    ips = _yield_repeated_creds_ips(tag, idx_ptrn, search_only=search_only)
    es_utils.tag_ips(idx_ptrn, ips, tag, tag_type=TagEnum.USER, bucketed=False)
    LOGGER.info(f"_tag_repeated_creds finished")


###############################################################################

BOT_TAG_PIPELINE = {
    "placebo-ip": tag_idx_placebo_ips,
    "other-placebo-ip": tag_other_placebo_ips,
    "mirai": tag_mirai_ips,
    "other-service-bot-ip": tag_other_services_bot_ips,
    "blocklist": tag_blocklist_ips,
    "bl": tag_blocklist_ipsets,
    "web-fingerprint": tag_web_fingerprints,
}