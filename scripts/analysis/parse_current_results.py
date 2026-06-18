#!/usr/bin/env python3
"""
Retrospective Result Parser for CIC-IDS-2017 Benchmark
Saves metrics from the user's completed execution to structured JSON and formatted TXT.
"""

import json
import os

# Define the absolute output path on the server
EBPF_DIR = "./data/processed/EBPF"

results = {
    "Friday-WorkingHours": {
        "partition": "labeled_Friday-WorkingHours.csv",
        "n_samples": 1787468,
        "n_features": 480,
        "macro_f1": 0.9991,
        "metrics": {
            "BENIGN": {"precision": 0.9992, "recall": 0.9994, "f1-score": 0.9993, "support": 319627},
            "DDoS_PortScan": {"precision": 0.9991, "recall": 0.9989, "f1-score": 0.9990, "support": 216614},
            "accuracy": 0.9992,
            "macro avg": {"precision": 0.9991, "recall": 0.9991, "f1-score": 0.9991, "support": 536241},
            "weighted avg": {"precision": 0.9992, "recall": 0.9992, "f1-score": 0.9992, "support": 536241}
        },
        "report": (
            "               precision    recall  f1-score   support\n\n"
            "       BENIGN     0.9992    0.9994    0.9993    319627\n"
            "DDoS_PortScan     0.9991    0.9989    0.9990    216614\n\n"
            "     accuracy                         0.9992    536241\n"
            "    macro avg     0.9991    0.9991    0.9991    536241\n"
            " weighted avg     0.9992    0.9992    0.9992    536241\n"
        )
    },
    "Thursday-WorkingHours": {
        "partition": "labeled_Thursday-WorkingHours.csv",
        "n_samples": 1220002,
        "n_features": 480,
        "macro_f1": 0.8889,
        "metrics": {
            "BENIGN": {"precision": 0.9347, "recall": 0.9855, "f1-score": 0.9594, "support": 291254},
            "WebAttack": {"precision": 0.9284, "recall": 0.7316, "f1-score": 0.8183, "support": 74747},
            "accuracy": 0.9337,
            "macro avg": {"precision": 0.9315, "recall": 0.8586, "f1-score": 0.8889, "support": 366001},
            "weighted avg": {"precision": 0.9334, "recall": 0.9337, "f1-score": 0.9306, "support": 366001}
        },
        "report": (
            "              precision    recall  f1-score   support\n\n"
            "      BENIGN     0.9347    0.9855    0.9594    291254\n"
            "   WebAttack     0.9284    0.7316    0.8183     74747\n\n"
            "    accuracy                         0.9337    366001\n"
            "   macro avg     0.9315    0.8586    0.8889    366001\n"
            "weighted avg     0.9334    0.9337    0.9306    366001\n"
        )
    },
    "Tuesday-WorkingHours": {
        "partition": "labeled_Tuesday-WorkingHours.csv",
        "n_samples": 1232640,
        "n_features": 480,
        "macro_f1": 0.9565,
        "metrics": {
            "BENIGN": {"precision": 0.9968, "recall": 0.9969, "f1-score": 0.9968, "support": 356348},
            "BruteForce": {"precision": 0.9167, "recall": 0.9158, "f1-score": 0.9162, "support": 13444},
            "accuracy": 0.9939,
            "macro avg": {"precision": 0.9568, "recall": 0.9563, "f1-score": 0.9565, "support": 369792},
            "weighted avg": {"precision": 0.9939, "recall": 0.9939, "f1-score": 0.9939, "support": 369792}
        },
        "report": (
            "              precision    recall  f1-score   support\n\n"
            "      BENIGN     0.9968    0.9969    0.9968    356348\n"
            "  BruteForce     0.9167    0.9158    0.9162     13444\n\n"
            "    accuracy                         0.9939    369792\n"
            "   macro avg     0.9568    0.9563    0.9565    369792\n"
            "weighted avg     0.9939    0.9939    0.9939    369792\n"
        )
    },
    "Wednesday-workingHours": {
        "partition": "labeled_Wednesday-workingHours.csv",
        "n_samples": 2171918,
        "n_features": 480,
        "macro_f1": 0.9985,
        "metrics": {
            "BENIGN": {"precision": 0.9985, "recall": 0.9989, "f1-score": 0.9987, "support": 378799},
            "DoS": {"precision": 0.9985, "recall": 0.9979, "f1-score": 0.9982, "support": 272777},
            "accuracy": 0.9985,
            "macro avg": {"precision": 0.9985, "recall": 0.9984, "f1-score": 0.9985, "support": 651576},
            "weighted avg": {"precision": 0.9985, "recall": 0.9985, "f1-score": 0.9985, "support": 651576}
        },
        "report": (
            "              precision    recall  f1-score   support\n\n"
            "      BENIGN     0.9985    0.9989    0.9987    378799\n"
            "         DoS     0.9985    0.9979    0.9982    272777\n\n"
            "    accuracy                         0.9985    651576\n"
            "   macro avg     0.9985    0.9984    0.9985    651576\n"
            "weighted avg     0.9985    0.9985    0.9985    651576\n"
        )
    }
}

if not os.path.exists(EBPF_DIR):
    print(f"[ERROR] Directory {EBPF_DIR} does not exist on this machine.")
    exit(1)

for key, data in results.items():
    json_path = os.path.join(EBPF_DIR, f"labeled_{key}_results.json")
    txt_path = os.path.join(EBPF_DIR, f"labeled_{key}_report.txt")
    
    with open(json_path, "w") as jf:
        json.dump(data, jf, indent=4)
        
    with open(txt_path, "w") as tf:
        tf.write(data["report"] + f"\n-> MACRO F1-SCORE: {data['macro_f1']:.4f}\n")
        
    print(f"[SUCCESS] Persisted retrospective results for {key}:")
    print(f"  -> {json_path}")
    print(f"  -> {txt_path}")
