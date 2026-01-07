import subprocess
import sys
import os


def run_step(description, command):
    print(f"\nRunning: {description}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print("Step failed. Exiting pipeline.")
        sys.exit(1)


if __name__ == "__main__":
    print("Starting Risk-Driven Cyber Threat Prioritization Pipeline")

    run_step(
        "Generating random security incidents",
        "python incident-generator.py"
    )

    run_step(
        "Converting incidents into structured findings",
        "python convert_random_to_findings.py"
    )

    run_step(
        "Running risk scoring and prioritization engine",
        "python engine-scorer.py"
    )

    for file in ["random_incident_dataset.csv", "data-findings.json"]:
        if os.path.exists(file):
            os.remove(file)

    print("\nPipeline completed successfully.")
    print("Final output generated: risk_report.csv")