import scripts.sysmon_config_run as sysmon_config_run
import scripts.sysmon_logs as sysmon_logs
import scripts.download_analytics as download_analytics
import scripts.generate_scripts as generate_scripts
import scripts.run_analyses as run_analyses
import scripts.generate_report as generate_report


# Funciones para cada paso del proceso
def update_sysmon():
    print("Updating/Installing Sysmon...")
    sysmon_config_run.main()
    print("Sysmon installed.")

def download_sysmon_logs():
    print("Downloading sysmon logs...")
    sysmon_logs.main()
    print("Sysmon logs downloaded.")

def download_analytics_data():
    print("Downloading analytics...")
    download_analytics.main()
    print("Analytics downloaded.")

def generate_analysis_scripts():
    print("Generating scripts...")
    generate_scripts.main()
    print("Scripts generated.")

def execute_analyses():
    print("Running analyses...")
    run_analyses.main()
    print("Analyses finished.")

def generate_final_report():
    print("Generating report...")
    generate_report.main()
    print("Report generated.")


def main():
    try:
        update_sysmon()
        download_sysmon_logs()
        download_analytics_data()
        generate_analysis_scripts()
        execute_analyses()
        generate_final_report()

    except Exception as e:
        print(f"Error during execution: {e}")


if __name__ == "__main__":
    main()
