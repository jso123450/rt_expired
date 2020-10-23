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
import scanner
import utils

# constants
SLEEP_DUR = 10


def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()


def main():
    # args = parse_args()
    # pdb.set_trace()

    # scan and unzip
    ctr, srvc_files = scanner.scan()

    # bulk index
    indexer.bulk_index(srvc_files)

    # cleanup
    scanner.cleanup(ctr)


if __name__ == "__main__":
    # while True:
    #     main()
    #     time.sleep(SLEEP_DUR)
    main()