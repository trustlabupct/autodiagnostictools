import os
import subprocess


def run_analyses():
    base_dir = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "GitHub",
        "autodiagnostictools",
        "carmitre_module",
    )
    scripts_dir = os.path.join(base_dir, "scripts", "generated")

    for script in os.listdir(scripts_dir):
        if script.startswith("analyze_") and script.endswith(".py"):
            subprocess.run(["python", os.path.join(scripts_dir, script)])


if __name__ == "__main__":
    run_analyses()
