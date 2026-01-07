import csv
import random


NUM_RECORDS = 100  


INCIDENT_TYPES = [
    "Credential Abuse",
    "Public App Exploitation",
    "Ransomware Execution",
    "Lateral Movement",
    "Data Exfiltration",
    "Reconnaissance Activity",
    "Malware Beaconing",
    "Privilege Escalation"
]


CATEGORY_ASSET_MAP = {
    "Credential Abuse": ("IAM", "Identity Platform"),
    "Public App Exploitation": ("AppSec", "Web Application"),
    "Ransomware Execution": ("Endpoint", "Workstations"),
    "Lateral Movement": ("Network", "Corporate Network"),
    "Data Exfiltration": ("Data", "Customer Data"),
    "Reconnaissance Activity": ("Network", "Public Infrastructure"),
    "Malware Beaconing": ("Endpoint", "Workstations"),
    "Privilege Escalation": ("IAM", "Directory Services")
}


TITLE_VARIANTS = {
    "Credential Abuse": [
        "Suspicious credential usage observed",
        "Abnormal authentication behavior detected"
    ],
    "Public App Exploitation": [
        "Exploit attempt against public web service",
        "Suspicious activity targeting web application"
    ],
    "Ransomware Execution": [
        "Ransomware-like behavior observed on endpoint",
        "Suspicious file encryption activity detected"
    ],
    "Lateral Movement": [
        "Suspicious lateral movement within network",
        "Unusual internal network activity observed"
    ],
    "Data Exfiltration": [
        "Unusual outbound data transfer detected",
        "Potential data exfiltration activity observed"
    ],
    "Reconnaissance Activity": [
        "Suspicious reconnaissance behavior observed",
        "Scanning activity detected from external source"
    ],
    "Malware Beaconing": [
        "Potential command-and-control communication observed",
        "Suspicious outbound beaconing behavior detected"
    ],
    "Privilege Escalation": [
        "Unauthorized privilege escalation attempt detected",
        "Suspicious elevation of privileges observed"
    ]
}

def generate_incident(i):
    incident = random.choice(INCIDENT_TYPES)
    category, asset = CATEGORY_ASSET_MAP[incident]

    exposure = random.choices(
        ["External", "Internal"],
        weights=[0.6, 0.4],
        k=1
    )[0]

    likelihood = random.randint(3, 5) if exposure == "External" else random.randint(1, 4)
    impact = random.randint(4, 5) if category in ["Data", "IAM"] else random.randint(3, 5)
    exploitability = random.randint(2, 5)
    business_criticality = random.randint(3, 5)
    control_coverage = random.randint(1, 4)
    detection_gap = random.random() < (0.6 if control_coverage <= 2 else 0.3)
    confidence = round(random.uniform(0.7, 0.95), 2)

    return {
        "id": f"INC-{i:05}",
        "title": random.choice(TITLE_VARIANTS[incident]),
        "category": category,
        "asset": asset,
        "exposure": exposure,
        "likelihood": likelihood,
        "impact": impact,
        "exploitability": exploitability,
        "business_criticality": business_criticality,
        "control_coverage": control_coverage,
        "detection_gap": detection_gap,
        "confidence": confidence
    }


with open("random_incident_dataset.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "id",
            "title",
            "category",
            "asset",
            "exposure",
            "likelihood",
            "impact",
            "exploitability",
            "business_criticality",
            "control_coverage",
            "detection_gap",
            "confidence"
        ]
    )
    writer.writeheader()

    for i in range(1, NUM_RECORDS + 1):
        writer.writerow(generate_incident(i))

print(f"random_incident_dataset.csv generated with {NUM_RECORDS} records")