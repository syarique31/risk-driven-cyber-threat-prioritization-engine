import pandas as pd
import json

# Load UNSW-NB15 dataset
df = pd.read_csv("unsw_nb15.csv")

# Keep only attack traffic
attacks = df[df["label"] == 1]

# Group attacks by category
attack_counts = attacks["attack_cat"].value_counts()

findings = []

# Convert each attack category into a security finding
for attack, count in attack_counts.items():
    finding = {
        "id": f"UNSW-{attack.upper()}",
        "title": f"{attack} attack activity detected",
        "category": "Network Security",
        "asset": "Public Network Infrastructure",
        "exposure": "External",

        # Heuristic scoring based on frequency
        "likelihood": min(5, count // 5000 + 1),
        "impact": 4,
        "exploitability": 4,
        "business_criticality": 4,
        "control_coverage": 3,
        "detection_gap": False,
        "confidence": 0.9
    }

    findings.append(finding)

# Write findings to JSON for the risk engine
with open("data-findings.json", "w") as f:
    json.dump(findings, f, indent=2)

print("data-findings.json generated from UNSW-NB15")