import json
import os


def load_process_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_registry_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_network_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_system_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_application_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_service_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def load_file_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []


def filter_suspicious_processes(process_logs, process_conditions):
    susp_processes = []
    for process in process_logs:
        cmd = process.get("command_line", "")
        exe = process.get("exe", "")
        image_path = process.get("image_path", "")
        process_path = process.get("process_path", "")
        parent_exe = process.get("parent_exe", "")
        key = process.get("key", "")
        if eval(process_conditions):
            susp_processes.append(process)
    return susp_processes


def filter_suspicious_registry_keys(registry_logs, registry_conditions):
    event_log_reg_keys = []
    for reg in registry_logs:
        key = reg.get("key", "")
        value = reg.get("value", "")
        if eval(registry_conditions):
            event_log_reg_keys.append(reg)
    return event_log_reg_keys


def filter_suspicious_network_logs(network_logs, network_conditions):
    susp_network_logs = []
    for log in network_logs:
        src_ip = log.get("source_ip", "")
        dst_ip = log.get("destination_ip", "")
        protocol = log.get("protocol", "")
        data = log.get("data", "")
        dest_port = log.get("dest_port", "")
        src_port = log.get("src_port", "")
        proto_info = log.get("proto_info", "")
        port = log.get("port", "")
        if eval(network_conditions):
            susp_network_logs.append(log)
    return susp_network_logs


def filter_suspicious_system_logs(system_logs, system_conditions):
    susp_system_logs = []
    for log in system_logs:
        event_id = log.get("event_id", "")
        event_message = log.get("event_message", "")
        raw_event = log.get("raw_event", "")
        log_name = log.get("log_name", "")
        event_code = log.get("event_code", "")
        object_type = log.get("object_type", "")
        subject_security_id = log.get("subject_security_id", "")
        event_code = log.get("EventCode", "")
        auth_package = log.get("AuthenticationPackageName", "")
        severity = log.get("Severity", "")
        logon_type = log.get("LogonType", "")
        if eval(system_conditions):
            susp_system_logs.append(log)
    return susp_system_logs


def filter_suspicious_application_logs(application_logs, application_conditions):
    susp_application_logs = []
    for log in application_logs:
        app_name = log.get("app_name", "")
        log_level = log.get("log_level", "")
        if eval(application_conditions):
            susp_application_logs.append(log)
    return susp_application_logs


def filter_suspicious_service_logs(service_logs, service_conditions):
    susp_service_logs = []
    for log in service_logs:
        image_path = log.get("image_path", "")
        if eval(service_conditions):
            susp_service_logs.append(log)
    return susp_service_logs


def filter_suspicious_file_logs(file_logs, file_conditions):
    susp_file_logs = []
    for log in file_logs:
        extension = log.get("extension", "")
        file_path = log.get("file_path", "")
        if eval(file_conditions):
            susp_file_logs.append(log)
    return susp_file_logs


def run_analysis(
    process_logs_file,
    registry_logs_file,
    network_logs_file,
    system_logs_file,
    application_logs_file,
    service_logs_file,
    file_logs_file,
    process_conditions,
    registry_conditions,
    network_conditions,
    system_conditions,
    application_conditions,
    service_conditions,
    file_conditions,
):
    process_logs = load_process_logs(process_logs_file)
    registry_logs = load_registry_logs(registry_logs_file)
    network_logs = load_network_logs(network_logs_file)
    system_logs = load_system_logs(system_logs_file)
    application_logs = load_application_logs(application_logs_file)
    service_logs = load_service_logs(service_logs_file)
    file_logs = load_file_logs(file_logs_file)

    suspicious_processes = filter_suspicious_processes(process_logs, process_conditions)
    suspicious_registry_keys = filter_suspicious_registry_keys(
        registry_logs, registry_conditions
    )
    suspicious_network_logs = filter_suspicious_network_logs(
        network_logs, network_conditions
    )
    suspicious_system_logs = filter_suspicious_system_logs(
        system_logs, system_conditions
    )
    suspicious_application_logs = filter_suspicious_application_logs(
        application_logs, application_conditions
    )
    suspicious_service_logs = filter_suspicious_service_logs(
        service_logs, service_conditions
    )
    suspicious_file_logs = filter_suspicious_file_logs(file_logs, file_conditions)

    return (
        suspicious_processes,
        suspicious_registry_keys,
        suspicious_network_logs,
        suspicious_system_logs,
        suspicious_application_logs,
        suspicious_service_logs,
        suspicious_file_logs,
    )


def save_results(
    suspicious_processes,
    suspicious_registry_keys,
    suspicious_network_logs,
    suspicious_system_logs,
    suspicious_application_logs,
    suspicious_service_logs,
    suspicious_file_logs,
    output_file,
):
    results = {
        "suspicious_processes": suspicious_processes,
        "suspicious_registry_keys": suspicious_registry_keys,
        "suspicious_network_logs": suspicious_network_logs,
        "suspicious_system_logs": suspicious_system_logs,
        "suspicious_application_logs": suspicious_application_logs,
        "suspicious_service_logs": suspicious_service_logs,
        "suspicious_file_logs": suspicious_file_logs,
    }

    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)


if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    process_logs_file = os.path.join(base_dir, "..", "..", "logs", "process_logs.json")
    registry_logs_file = os.path.join(
        base_dir, "..", "..", "logs", "registry_logs.json"
    )
    network_logs_file = os.path.join(base_dir, "..", "..", "logs", "network_logs.json")
    system_logs_file = os.path.join(base_dir, "..", "..", "logs", "system_logs.json")
    application_logs_file = os.path.join(
        base_dir, "..", "..", "logs", "application_logs.json"
    )
    service_logs_file = os.path.join(base_dir, "..", "..", "logs", "service_logs.json")
    file_logs_file = os.path.join(base_dir, "..", "..", "logs", "file_logs.json")
    output_file = os.path.join(
        base_dir, "..", "..", "output", "suspicious_results_{analytic_id}.json"
    )

    process_conditions = "{process_conditions}"
    registry_conditions = "{registry_conditions}"
    network_conditions = "{network_conditions}"
    system_conditions = "{system_conditions}"
    application_conditions = "{application_conditions}"
    service_conditions = "{service_conditions}"
    file_conditions = "{file_conditions}"

    (
        suspicious_processes,
        suspicious_registry_keys,
        suspicious_network_logs,
        suspicious_system_logs,
        suspicious_application_logs,
        suspicious_service_logs,
        suspicious_file_logs,
    ) = run_analysis(
        process_logs_file,
        registry_logs_file,
        network_logs_file,
        system_logs_file,
        application_logs_file,
        service_logs_file,
        file_logs_file,
        process_conditions,
        registry_conditions,
        network_conditions,
        system_conditions,
        application_conditions,
        service_conditions,
        file_conditions,
    )
    save_results(
        suspicious_processes,
        suspicious_registry_keys,
        suspicious_network_logs,
        suspicious_system_logs,
        suspicious_application_logs,
        suspicious_service_logs,
        suspicious_file_logs,
        output_file,
    )

    print(f"Procesos sospechosos encontrados: {len(suspicious_processes)}")
    print(
        f"Claves de registro sospechosas encontradas: {len(suspicious_registry_keys)}"
    )
    print(f"Logs de red sospechosos encontrados: {len(suspicious_network_logs)}")
    print(f"Logs de sistema sospechosos encontrados: {len(suspicious_system_logs)}")
    print(
        f"Logs de aplicación sospechosos encontrados: {len(suspicious_application_logs)}"
    )
    print(f"Logs de servicio sospechosos encontrados: {len(suspicious_service_logs)}")
    print(f"Archivos sospechosos encontrados: {len(suspicious_file_logs)}")
