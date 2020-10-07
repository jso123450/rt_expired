""" Steps

1. Scan directories for decompressed files
    a. If none, decompress some
2. Pass these files to the parser to extract dicts/JSON objects to index
3. Pass the generator returned by the parser to es.helpers.bulk
"""

import argparse
import concurrent.futures as cfutures

import utils


def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()


def main():
    args = parse_args()


if __name__ == "__main__":
    main()