import argparse
from datetime import datetime
import json
from json.decoder import JSONDecodeError

import pdb


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, help="Results file.")
    parser.add_argument("--rrtype", type=str, help="RRtype", default="A")
    return parser.parse_args()


def read_file(_file, rrtype):
    results = []
    with open(_file, "r") as f:
        for line in f:
            if len(line.strip()) == 0:
                continue
            obj = json.loads(line)
            if obj["rrtype"] == rrtype:
                time_key = "time_last" if "time_last" in obj else "zone_time_last"
                obj["sort_key"] = datetime.strptime(obj[time_key], "%Y-%m-%dT%H:%M:%SZ")
                if obj["sort_key"].year < 2017:
                    continue
                results.append(obj)
    return results


def main():
    args = parse_args()
    results = read_file(args.file, args.rrtype)
    results.sort(key=lambda x: x["sort_key"])
    for res in results:
        del res["sort_key"]
        print(json.dumps(res))


if __name__ == "__main__":
    main()