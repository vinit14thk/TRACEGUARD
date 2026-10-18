from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"

SCRIPTS = [
    ("Suspicious Activity Detection", "src/detection_engine.py"),
    ("Evaluation", "src/evaluation.py"),
    ("Evidence Graph Visualization", "src/visualize_graph.py"),
    ("Incident Report", "src/incident_report.py"),
]


def main():
    if not PYTHON.exists():
        print("ERROR: Project virtual environment was not found.")
        print("Expected:", PYTHON)
        return 1

    for title, script in SCRIPTS:
        script_path = ROOT / script

        print("\n" + "=" * 55)
        print(title)
        print("=" * 55)

        if not script_path.exists():
            print("ERROR: Missing script:", script)
            return 1

        result = subprocess.run(
            [str(PYTHON), str(script_path)],
            cwd=ROOT,
        )

        if result.returncode != 0:
            print(f"\nERROR: {title} failed.")
            return result.returncode

    print("\n" + "=" * 55)
    print("TRACEGUARD RUN COMPLETED SUCCESSFULLY")
    print("=" * 55)
    return 0


if __name__ == "__main__":
    sys.exit(main())