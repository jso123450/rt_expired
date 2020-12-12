import argparse
import json
import requests
import os

import pdb

# from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()
APIKEY = os.getenv("FARSIGHT_APIKEY")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", type=str, help="Domain to look up.")
    parser.add_argument("--ip", type=str, help="IP to look up.")
    parser.add_argument("--quota", action="store_true", default=False)
    return parser.parse_args()


def get_farsight_domain(domain):
    if domain is None:
        return None
    url = "https://api.dnsdb.info/lookup/rrset/name/*.%s?humantime=t" % domain
    headers = {"X-API-Key": APIKEY, "Accept": "application/json"}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        if response.status_code == 429:
            print(429)
        return {}

    content = response.content.decode("utf-8")
    return content

    # results = []
    # for line in content.split("\n"):
    #     if line == "":
    #         continue
    #     currentLine = json.loads(line)
    #     results.append(currentLine)

    # return results


def get_farsight_ip(ip):
    if ip is None:
        return None
    url = "https://api.dnsdb.info/lookup/rdata/ip/%s?humantime=t" % ip
    headers = {"X-API-Key": APIKEY, "Accept": "application/json"}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        if response.status_code == 429:
            print(429)
        return {}

    content = response.content.decode("utf-8")
    return content

    # results = []
    # for line in content.split("\n"):
    #     if line == "":
    #         continue
    #     currentLine = json.loads(line)
    #     results.append(currentLine)

    # return results


def get_farsight_quota():
    url = "https://api.dnsdb.info/lookup/rate_limit"

    headers = {"X-API-Key": APIKEY}

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {}

    content = response.content.decode("utf-8")
    return content


def print_data(domain_data, ip_data, quota_data):
    if domain_data is not None:
        # print(f"------------ DOMAIN DATA ------------")
        print(domain_data)
        # print(json.dumps(domain_data))
    if ip_data is not None:
        # print(f"------------ IP DATA ------------")
        print(ip_data)
        # print(json.dumps(ip_data))
    if quota_data is not None:
        # print(f"------------ QUOTA DATA ------------")
        print(quota_data)
        # print(json.dumps(quota_data))


def main(**kwargs):
    _domain = kwargs.get("domain", None)
    _ip = kwargs.get("ip", None)
    _quota = kwargs.get("quota", False)
    if _domain is None and _ip is None and _quota is False:
        args = parse_args()
        _domain = args.domain
        _ip = args.ip
        _quota = args.quota
    if _domain is None and _ip is None and not _quota:
        print("No argument passed.")
        return (None, None, None)
    domain_data = get_farsight_domain(_domain)
    ip_data = get_farsight_ip(_ip)
    quota_data = get_farsight_quota() if _quota else None
    print_data(domain_data, ip_data, quota_data)
    return (domain_data, ip_data, quota_data)


if __name__ == "__main__":
    main()
