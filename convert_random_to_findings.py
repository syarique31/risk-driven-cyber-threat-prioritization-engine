import csv
import json

INPUT_CSV = "random_incident_dataset.csv"
OUTPUT_JSON = "data-findings.json"

findings = []

with open(INPUT_CSV, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        findings.append({
            "id": row["id"],
            "title": row["title"],
            "category": row["category"],
            "asset": row["asset"],
            "exposure": row["exposure"],
            "likelihood": int(row["likelihood"]),
            "impact": int(row["impact"]),
            "exploitability": int(row["exploitability"]),
            "business_criticality": int(row["business_criticality"]),
            "control_coverage": int(row["control_coverage"]),
            "detection_gap": row["detection_gap"] == "TRUE",
            "confidence": float(row["confidence"])
        })

with open(OUTPUT_JSON, "w") as f:
    json.dump(findings, f, indent=2)

print(f"{OUTPUT_JSON} generated from {INPUT_CSV}")