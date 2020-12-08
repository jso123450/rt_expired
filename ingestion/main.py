""" Imports container log files into Elastisearch.

1. Scan directories for decompressed files
    a. If none, decompress some
2. Pass these files to the parser to extract dicts/JSON objects to index
3. Pass the generator returned by the parser to es.helpers.bulk
"""

# stdlib
import argparse
import time
import pdb

# proj
import indexer
import reindexer
import scanner
import utils

# constants
SLEEP_DUR = 10


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("task", type=str, help="'index' or 'reindex'")
    return parser.parse_args()


def main(task):
    if task == "index":
        return
        # scan and unzip
        ctr, srvc_files = scanner.scan()

        # bulk index
        indexer.bulk_index(ctr, srvc_files)

        # cleanup
        scanner.cleanup(ctr)
    elif task == "reindex":
        reindexer.reindex()


if __name__ == "__main__":
    args = parse_args()
    while True:
        main(args.task)
        if args.task == "reindex":
            break
        time.sleep(SLEEP_DUR)