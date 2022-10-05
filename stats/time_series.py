# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
from IPython import get_ipython

# %%
get_ipython().run_line_magic("load_ext", "autotime")

# %%
# from collections import defaultdict
import json
import logging
from pathlib import Path
import pdb
# import re

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, A, Q
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
# from wordcloud import WordCloud, STOPWORDS

import utils
import es_utils
import plot_utils


# from utils
CONFIG = utils.get_config()
CTRS = utils.get_containers()
PLACEBOS = utils.get_placebos()
NONPLACEBOS = utils.get_nonplacebos()

# constants


# artifacts
BASE_DIR = Path(CONFIG["ARTIFACT_DIR"])



# globals
LOGGER = utils.get_logger("ftp-telnet_stats", BASE_DIR / "ftp-telnet.log", logging.INFO)

