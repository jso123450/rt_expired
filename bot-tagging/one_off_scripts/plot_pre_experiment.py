from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
import sys
import pdb

MAIN_DIR = Path("/home/ubuntu/repos/rt_expired/bot-tagging")
sys.path.append(str(MAIN_DIR))

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

###############################################################################

DATA_DIR = MAIN_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PLOT_DIR = MAIN_DIR / "plots" / "pre_experiment"
PLOT_DIR.mkdir(exist_ok=True)

DATA_FILE = DATA_DIR / "pre_experiment_totals.csv"
PLOT_FILE = PLOT_DIR / "scatter_pre-experiment.png"

###############################################################################


def get_data(_file=DATA_FILE):
    return pd.read_csv(_file)


def plot_scatter(df):
    def _get_best_fit(x, y):
        poly = np.polynomial.Polynomial.fit(x, y, deg=1)
        return poly
        # return np.unique(x), np.poly1d(np.polyfit(x, y, 1))(np.unique(x))

    # _, ax = plt.subplots(1, 1)
    # ax.scatter(df.before, df.after)
    # ax.set_xscale("log")
    # ax.set_yscale("log")
    # ax.set_xlabel("Before drop")
    # ax.set_ylabel("After drop")

    plt.figure(figsize=(6, 3))
    plt.xscale("log")
    plt.yscale("log")

    ax = sns.scatterplot(x=df.before, y=df.after, alpha=0.5, s=5, label="Expired domains")

    poly = _get_best_fit(df.before, df.after)
    xx, yy = poly.linspace()
    # poly_string = f"$y = {poly.coef[1]:.2f}x + {poly.coef[0]:.2f}$"
    poly_string = "Fitted 1-degree polynomial (least squares)"
    plt.plot(xx, yy, label=poly_string, color="orange")

    plt.axhline(10 ** 4, linestyle="--")
    plt.axvline(10 ** 6, linestyle="--")

    handles, labels = plt.gca().get_legend_handles_labels()
    order = [1, 0]
    plt.legend([handles[idx] for idx in order], [labels[idx] for idx in order])

    plt.ylim(1, max(df.after))
    plt.xlim(1, max(df.before))
    ax.set_xlabel("# lookups at the time of dropping")
    ax.set_ylabel("# lookups two weeks \nafter re-registration")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(PLOT_FILE)


###############################################################################


def main():
    df = get_data()
    plot_scatter(df)


if __name__ == "__main__":
    main()