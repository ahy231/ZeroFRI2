#!/usr/bin/env python3

import os
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np


sizes = np.arange(10, 23)  # polynomial sizes (log2)

data = {
    "Basefold": {
        "pg": [22, 51, 90, 108, 193, 366, 997, 1650, 2819, 7505, 16292, 43314, 155459],
        "ps": [48085760, 53427200, 58973952, 64726016, 70683392, 76846080, 83214080,
               89787392, 96566016, 103549952, 110739200, 118133760, 125733632],
        "vt": [72, 66, 80, 120, 108, 106, 106, 146, 118, 136, 101, 133, 218],
    },
    "Brakedown Spec 1": {
        "pg": [247, 271, 224, 371, 323, 406, 631, 909, 1541, 2871, 5981, 18520, 64669],
        "ps": [571307520, 619637248, 668753408, 719442432, 796345856, 879540736, 974625792,
               1093472256, 1283640832, 1473790464, 1854126080, 2186882048, 2947551744],
        "vt": [905, 895, 942, 1235, 1003, 1212, 1406, 1808, 2122, 2855, 3746, 5268, 7114],
    },
    "Brakedown Spec 3": {
        "pg": [111, 141, 151, 167, 209, 295, 451, 739, 1258, 2720, 5305, 17814, 81316],
        "ps": [284358144, 308775424, 333979136, 372290048, 413746688, 461006848, 520289280,
               614808064, 709742080, 898778112, 1065015296, 1443085824, 1751929344],
        "vt": [360, 382, 434, 492, 610, 694, 947, 1055, 1435, 1740, 2684, 3315, 5883],
    },
    "Brakedown Spec 6": {
        "pg": [69, 76, 207, 116, 163, 248, 427, 680, 1346, 2597, 6086, 17907, 71403],
        "ps": [162301440, 176547328, 197346816, 219719168, 246636544, 277921792, 331755008,
               380866048, 488530944, 573293568, 788621824, 944687616, 1375342592],
        "vt": [213, 240, 317, 361, 406, 565, 639, 917, 1075, 1626, 1926, 3461, 4066],
    },
    "Gemini": {
        "pg": [228, 296, 645, 978, 1864, 3260, 4279, 8742, 15882, 31391, 74933, 167588, 373700],
        "ps": [36864, 39936, 43008, 46080, 49152, 52224, 55296, 58368, 61440, 64512,
               67584, 70656, 73728],
        "vt": [10, 9, 13, 10, 20, 14, 13, 15, 17, 19, 21, 53, 51],
    },
    "Zeromorph-FRI": {
        "pg": [43, 52, 106, 167, 363, 684, 1263, 2764, 5838, 17071, 50730, np.nan, np.nan],
        "ps": [11052032, 12102400, 13186560, 14304512, 15456256, 16641792, 17861120,
               19114240, 20401152, 21721856, 23076352, np.nan, np.nan],
        "vt": [22, 20, 20, 21, 22, 23, 32, 29, 36, 33, 62, np.nan, np.nan],
    },
    "Hyrax": {
        "pg": [241, 409, 618, 1222, 1879, 2735, 4636, 9186, 16496, 28178, 52824, 102261, 224207],
        "ps": [50944, 54272, 72960, 76288, 111360, 114688, 182528, 185856, 319232,
               322560, 587008, 590336, 1116928],
        "vt": [26, 22, 56, 49, 76, 84, 123, 152, 235, 338, 444, 548, 1484],
    },
}


def plot_metric(metric_key, ylabel, fname, title):
    fig, ax = plt.subplots(figsize=(9, 5))
    for name, metrics in data.items():
        ax.plot(sizes, metrics[metric_key], label=name)

    ax.set_yscale("log")
    ax.set_xlabel("Polynomial size (log₂)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, which="both", ls="--", alpha=0.4)
    # legend outside on the right
    ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", borderaxespad=0)

    fig.tight_layout()
    out_dir = Path("docs/img")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / fname
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"✓ saved {out_path}")
    plt.show()  # comment this out if you don’t want an interactive window


plot_metric("pg", "Proof-generation time (ms)",
            "proof_gen_time.png",
            "Proof Generation Time vs Polynomial Size")

plot_metric("ps", "Proof size (bits)",
            "proof_size.png",
            "Proof Size vs Polynomial Size")

plot_metric("vt", "Verification time (ms)",
            "verification_time.png",
            "Verification Time vs Polynomial Size")
