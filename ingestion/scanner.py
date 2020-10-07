import glob
import os
from pathlib import Path


def scan(dirs):
    """Scans the directories for files to process.

    Parameters
    ----------
    dirs : {service : directory}

    Returns
    -------
    files : {service : iterator}
    """
    files = {}
    for srvc in dirs:
        file_glob = dirs[srvc]
        files[srvc] = glob.iglob(file_glob)
    return files