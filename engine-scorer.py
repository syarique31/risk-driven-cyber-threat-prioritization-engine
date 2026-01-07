import json
import csv


def load_findings(path):  # Read security findings from a JSON file
    with open(path, "r") as f:
        return json.load(f)


def calculate_base_risk(finding):  # Calculate technical severity without business context
    return (
        finding["likelihood"]
        * finding["impact"]
        * finding["exploitability"]
    )


def apply_modifiers(base_risk, finding):  # Adjust risk using exposure, controls, and detection factors
    risk = base_risk

    if finding["exposure"] == "External":
        risk *= 1.3

    if finding["business_criticality"] >= 4:
        risk *= 1.2

    if finding["control_coverage"] <= 2:
        risk *= 1.1
    elif finding["control_coverage"] >= 4:
        risk *= 0.7

    if finding["detection_gap"]:
        risk *= 1.15

    risk *= finding["confidence"]
    return risk


def normalize(score, max_score):  # Convert raw risk scores to a 0–100 scale
    return round((score / max_score) * 100, 2)


def assign_tier(score):  # Map normalized score to a severity tier
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


RECOMMENDATIONS = {
    "Authentication": "Enforce MFA, strengthen password policy, and apply rate limiting.",
    "Identity & Access Management": "Review privileged access, enforce least privilege, and audit permissions.",
    "Cloud Security": "Restrict public access, review storage permissions, and enable access logging.",
    "Vulnerability Management": "Apply patches immediately and enforce patch SLAs for exposed systems."
}


def get_recommendation(finding):  # Return remediation guidance based on issue type
    return RECOMMENDATIONS.get(
        finding["category"],
        "Review security controls and apply appropriate mitigations."
    )


def write_csv(results, filename="risk_report.csv"):  # Export the final risk report as a CSV file
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)


if __name__ == "__main__":  # Run the full risk scoring and reporting workflow
    findings = load_findings("data-findings.json")
    results = []

    scored = []
    for f in findings:
        base = calculate_base_risk(f)
        final = apply_modifiers(base, f)
        scored.append((f, base, final))

    max_final_risk = max(item[2] for item in scored)

    for f, base, final in scored:
        score = normalize(final, max_final_risk)
        tier = assign_tier(score)

        results.append({
            "ID": f["id"],
            "Title": f["title"],
            "Category": f["category"],
            "Asset": f["asset"],
            "Base Risk": round(base, 2),
            "Final Risk": round(final, 2),
            "Score (0-100)": score,
            "Tier": tier,
            "Recommendation": get_recommendation(f),
            "Confidence": f["confidence"]
        })
    
    results.sort(key=lambda x: x["Final Risk"], reverse=True)

    write_csv(results)
    print(" Risk report generated: risk_report.csv")