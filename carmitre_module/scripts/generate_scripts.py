import os
import codecs
import re

base_dir = os.path.join(os.path.expanduser("~"), "Documents", "TrustLab", "Car_mitre")
analytics_dir = os.path.join(base_dir, "analytics")
scripts_dir = os.path.join(base_dir, "scripts", "generated")

if not os.path.exists(scripts_dir):
    os.makedirs(scripts_dir)

debug_file_path = os.path.join(scripts_dir, "depuracion_resultados.txt")
debug_file = open(debug_file_path, "w", encoding="utf-8")


def debug(message):
    print(message)
    debug_file.write(message + "\n")


script_template = """
import json
import os

def load_process_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_registry_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_network_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_system_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_application_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_service_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_file_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []

def load_flow_start_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {{file_path}}")
        return []
    


def filter_suspicious_processes(process_logs):
    susp_processes = []
    for process in process_logs:
        exe = process.get("exe", "")
        cmd = process.get("command_line", "")
        image_path = process.get("image_path", "")
        process_path = process.get("process_path", "")
        parent_exe = process.get("parent_exe", "")
        key = process.get("key", "")
        parent_image_path = process.get("parent_image_path", "")
        if {conditions}:
            susp_processes.append(process)
    return susp_processes

def filter_suspicious_registry_keys(registry_logs):
    event_log_reg_keys = []
    for reg in registry_logs:
        key = reg.get("Key", "")
        value = reg.get("value", "")
        key = reg.get("key", "")
        if {registry_conditions}:
            event_log_reg_keys.append(reg)
    return event_log_reg_keys

def filter_suspicious_network_logs(network_logs):
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
        data = log.get("data", "")
        if {network_conditions}:
            susp_network_logs.append(log)
    return susp_network_logs

def filter_suspicious_system_logs(system_logs):
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
        param1 = log.get("param1", "")
        param2 = log.get("param2", "")
        if {system_conditions}:
            susp_system_logs.append(log)
    return susp_system_logs

def filter_suspicious_application_logs(application_logs):
    susp_app_logs = []
    for log in application_logs:
        app = log.get("application", "")
        log_level = log.get("log_level", "")
        if {application_conditions}:
            susp_app_logs.append(log)
    return susp_app_logs

def filter_suspicious_service_logs(service_logs):
    susp_service_logs = []
    for log in service_logs:
        image_path = log.get("image_path", "")
        if {service_conditions}:
            susp_service_logs.append(log)
    return susp_service_logs

    
def filter_suspicious_file_logs(file_logs):
    susp_file_logs = []
    for log in file_logs:
        extension = log.get("extension", "")
        file_path = log.get("file_path", "")
        image_path = log.get("image_path", "")
        if {file_conditions}:
            susp_file_logs.append(log)
    return susp_file_logs

def run_analysis(process_logs_file, registry_logs_file, network_logs_file, system_logs_file, application_logs_file, service_logs_file, file_logs_file):
    process_logs = load_process_logs(process_logs_file)
    registry_logs = load_registry_logs(registry_logs_file)
    network_logs = load_network_logs(network_logs_file)
    system_logs = load_system_logs(system_logs_file)
    application_logs = load_application_logs(application_logs_file)
    service_logs = load_service_logs(service_logs_file)
    file_logs = load_file_logs(file_logs_file)
    
    suspicious_processes = filter_suspicious_processes(process_logs)
    suspicious_registry_keys = filter_suspicious_registry_keys(registry_logs)
    suspicious_network_logs = filter_suspicious_network_logs(network_logs)
    suspicious_system_logs = filter_suspicious_system_logs(system_logs)
    suspicious_application_logs = filter_suspicious_application_logs(application_logs)
    suspicious_service_logs = filter_suspicious_service_logs(service_logs)
    suspicious_file_logs = filter_suspicious_file_logs(file_logs)

    return suspicious_processes, suspicious_registry_keys, suspicious_network_logs, suspicious_system_logs, suspicious_application_logs, suspicious_service_logs, suspicious_file_logs

def save_results(suspicious_processes, suspicious_registry_keys, suspicious_network_logs, suspicious_system_logs, suspicious_application_logs, suspicious_service_logs, suspicious_file_logs, output_file):
    results = {{
        "suspicious_processes": suspicious_processes,
        "suspicious_registry_keys": suspicious_registry_keys,
        "suspicious_network_logs": suspicious_network_logs,
        "suspicious_system_logs": suspicious_system_logs,
        "suspicious_application_logs": suspicious_application_logs,
        "suspicious_service_logs": suspicious_service_logs,
        "suspicious_file_logs": suspicious_file_logs
    }}
    
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    with open(output_file, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=4)

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    process_logs_file = os.path.join(base_dir, "..", "..", "logs", "process_logs.json")
    registry_logs_file = os.path.join(base_dir, "..", "..", "logs", "registry_logs.json")
    network_logs_file = os.path.join(base_dir, "..", "..", "logs", "network_logs.json")
    system_logs_file = os.path.join(base_dir, "..", "..", "logs", "system_logs.json")
    application_logs_file = os.path.join(base_dir, "..", "..", "logs", "application_logs.json")
    service_logs_file = os.path.join(base_dir, "..", "..", "logs", "service_logs.json")
    file_logs_file = os.path.join(base_dir, "..", "..", "logs", "file_logs.json")
    output_file = os.path.join(base_dir, "..", "..", "output", "suspicious_results_{analytic_id}.json")
    
    suspicious_processes, suspicious_registry_keys, suspicious_network_logs, suspicious_system_logs, suspicious_application_logs, suspicious_service_logs, suspicious_file_logs = run_analysis(process_logs_file, registry_logs_file, network_logs_file, system_logs_file, application_logs_file, service_logs_file, file_logs_file)
    save_results(suspicious_processes, suspicious_registry_keys, suspicious_network_logs, suspicious_system_logs, suspicious_application_logs, suspicious_service_logs, suspicious_file_logs, output_file)
    
    print(f"Procesos sospechosos encontrados: {{len(suspicious_processes)}}")
    print(f"Claves de registro sospechosas encontradas: {{len(suspicious_registry_keys)}}")
    print(f"Logs de red sospechosos encontrados: {{len(suspicious_network_logs)}}")
    print(f"Logs de sistema sospechosos encontrados: {{len(suspicious_system_logs)}}")
    print(f"Logs de aplicación sospechosos encontrados: {{len(suspicious_application_logs)}}")
    print(f"Logs de servicio sospechosos encontrados: {{len(suspicious_service_logs)}}")
    print(f"Archivos sospechosos encontrados: {{len(suspicious_file_logs)}}")
"""


def generate_script(analytic_id, pseudocode):
    conditions = extract_conditions(pseudocode)

    script_content = script_template.format(
        conditions=(
            " or ".join(conditions["process"]) if conditions["process"] else "False"
        ),
        registry_conditions=(
            " or ".join(conditions["registry"]) if conditions["registry"] else "False"
        ),
        network_conditions=(
            " or ".join(conditions["network"]) if conditions["network"] else "False"
        ),
        system_conditions=(
            " or ".join(conditions["system"]) if conditions["system"] else "False"
        ),
        application_conditions=(
            " or ".join(conditions["application"])
            if conditions["application"]
            else "False"
        ),
        service_conditions=(
            " or ".join(conditions["service"]) if conditions["service"] else "False"
        ),
        file_conditions=(
            " or ".join(conditions["file"]) if conditions["file"] else "False"
        ),
        analytic_id=analytic_id,
    )

    with codecs.open(
        os.path.join(scripts_dir, f"analyze_{analytic_id}.py"), "w", encoding="utf-8"
    ) as script_file:
        script_file.write(script_content)


def extract_conditions(pseudocode):
    conditions = {
        "process": [],
        "registry": [],
        "network": [],
        "system": [],
        "application": [],
        "service": [],
        "file": [],
    }

    lines = pseudocode.split("\n")
    for line in lines:
        line = line.strip()
        debug(f"Processing line: {line}")

        # Process conditions
        if (
            "command_line" in line
            or "command_line CONTAINS" in line
            or "exe =" in line
            or "exe=" in line
            or "parent_exe" in line
            or "image_path" in line
            or "process_path" in line
            or "key" in line
            or "parent_image_path" in line
        ):

            command_line = None
            key_condition = None
            exe_condition = None
            parent_exe_condition = None
            image_path_condition = None
            process_path_condition = None
            parent_image_path_condition = None
            if "command_line CONTAINS" in line:
                command_line = (
                    line.split("command_line CONTAINS")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                    .replace("\\", "")
                )
            if "command_line ==" in line:
                command_line = (
                    line.split("command_line ==")[1]
                    .split()[0]
                    .strip('()"*')
                    .replace("*", "")
                    .replace("\\", "")
                    .replace('"', '\\"')
                )
            if "key =" in line:
                key_condition = (
                    line.split("key =")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                    .replace("\\", "")
                )
            if "exe =" in line:
                exe_condition = (
                    line.split("exe =")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "exe=" in line:
                exe_condition = (
                    line.split("exe=")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "parent_exe =" in line:
                parent_exe_condition = (
                    line.split("parent_exe =")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "image_path ==" in line:
                image_path_condition = (
                    line.split("image_path ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                    .replace("\\", "")
                )
            if "process_path ==" in line:
                process_path_condition = (
                    line.split("process_path ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "parent_image_path ==" in line:
                parent_image_path_condition = (
                    line.split("parent_image_path ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )

            if command_line:
                conditions["process"].append(f'cmd == "{command_line}"')
            if key_condition:
                conditions["process"].append(f'key == "{key_condition}"')
            if exe_condition:
                conditions["process"].append(f'exe == "{exe_condition}"')
            if parent_exe_condition:
                conditions["process"].append(f'parent_exe == "{parent_exe_condition}"')
            if image_path_condition:
                conditions["process"].append(f'image_path == "{image_path_condition}"')
            if process_path_condition:
                conditions["process"].append(
                    f'process_path == "{process_path_condition}"'
                )
            if parent_image_path_condition:
                conditions["process"].append(
                    f'parent_image_path == "{parent_image_path_condition}"'
                )

        # File conditions
        if "extension =" in line or "file_path =" in line or "image_path !=" in line:
            extension_condition = None
            file_path_condition = None
            image_path_condition = None
            if "image_path !=" in line:
                image_path_condition = (
                    line.split("image_path !=")[1]
                    .strip()
                    .strip('()"*')
                    .replace("*", "")
                    .replace('"', '"')
                    .replace('"', "")
                )
            if "extension =" in line:
                extension_condition = (
                    line.split("extension =")[1]
                    .strip()
                    .strip('()"*')
                    .replace("*", "")
                    .replace('"', '"')
                    .replace('"', "")
                )
            if "file_path =" in line:
                file_path_condition = (
                    line.split("file_path =")[1]
                    .strip()
                    .strip("()*")
                    .replace("*", "")
                    .replace('"', '"')
                    .replace('"', "")
                )
            if file_path_condition:
                conditions["file"].append(f'"{file_path_condition}" in file_path')
            if extension_condition:
                conditions["file"].append(f'"{extension_condition}" in extension')
            if image_path_condition:
                conditions["file"].append(f'"{image_path_condition}" in image_path')
            if image_path_condition and file_path_condition:
                debug(
                    f"Extracted file condition: {image_path_condition}, {file_path_condition}"
                )
                conditions["file"].append(
                    f'"{image_path_condition}" in image_path and "{file_path_condition}" in file_path'
                )
            if extension_condition and file_path_condition:
                debug(
                    f"Extracted file condition: {extension_condition}, {file_path_condition}"
                )
                conditions["file"].append(
                    f'"{extension_condition}" in extension and "{file_path_condition}" in file_path'
                )
            # Menajar casos donde solo exista una condicion
            elif extension_condition:
                conditions["file"].append(f'"{extension_condition}" in extension')
            elif file_path_condition:
                conditions["file"].append(f'"{file_path_condition}" in file_path')

        # Service conditions
        if "image_path =" in line:
            image_path_condition = (
                line.split("image_path =")[1]
                .strip()
                .strip("()*")
                .replace("*", "")
                .replace('"', '\\"')
            )
            debug(f"Extracted service condition: {image_path_condition}")
            conditions["service"].append(f'"{image_path_condition}" in image_path')

        if "image_path does not contain" in line:
            excludes = (
                line.split("image_path does not contain")[1]
                .strip()
                .strip("[]")
                .replace('"', "")
                .split(",")
            )
            exclude_conditions = [
                f'"{exclude.strip()}" not in image_path' for exclude in excludes
            ]
            final_exclude_condition = " and ".join(exclude_conditions)
            debug(f"Extracted service exclusion condition: {final_exclude_condition}")
            conditions["service"].append(final_exclude_condition)

        # Task conditions

        # Registry conditions
        if "Key=" in line or "value=" in line or "key =" in line:
            key_condition = None
            value_condition = None
            if "Key=" in line:
                key_condition = line.split("Key=")[1].split()[0].strip(' "*')
            if "value=" in line:
                value_condition = line.split("value=")[1].split()[0].strip(' "*')
            if "key =" in line:
                key_condition = (
                    line.split("key =")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                    .replace("\\", "")
                )
            if key_condition:
                conditions["registry"].append(f'"{key_condition}" in key')
            if key_condition and value_condition:
                debug(
                    f"Extracted registry condition: {key_condition}, {value_condition}"
                )
                conditions["registry"].append(
                    f'"{key_condition}" in key and "{value_condition}" in value'
                )
            elif value_condition:
                debug(f"Extracted registry condition: {value_condition}")
                conditions["registry"].append(f'"{value_condition}" in value')

        # Network conditions
        if (
            "source_ip CONTAINS" in line
            or "dest_port ==" in line
            or "protocol ==" in line
            or "proto_info" in line
            or "dest_port >=" in line
            or "src_port >=" in line
            or "port ==" in line
        ):
            src_ip_condition = None
            dest_port_condition = None
            protocol_condition = None
            src_port_condition = None
            proto_info_condition = None
            port_condition = None

            if "source_ip CONTAINS" in line:
                src_ip_condition = (
                    line.split("source_ip CONTAINS")[1].split()[0].strip(' "*')
                )
            if "dest_port ==" in line:
                dest_port_condition = (
                    line.split("dest_port ==")[1].split()[0].strip(' "*')
                )
            if "protocol ==" in line:
                protocol_condition = (
                    line.split("protocol ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "proto_info" in line:
                proto_info_condition = (
                    line.split("proto_info")[1]
                    .strip()
                    .strip("()*")
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "dest_port >=" in line:
                dest_port_condition = (
                    line.split("dest_port >=")[1].split()[0].strip(' "*')
                )
            if "src_port >=" in line:
                src_port_condition = (
                    line.split("src_port >=")[1].split()[0].strip(' "*')
                )
            if "port ==" in line:
                port_condition = (
                    line.split("port ==")[1]
                    .split()[0]
                    .strip(' "*')
                    .strip('()"')
                    .replace("\\", "")
                    .replace('"', '\\"')
                )
            if port_condition:
                conditions["network"].append(f'"{port_condition}" in port')
            if src_port_condition:
                conditions["network"].append(f'"{src_port_condition}" in src_port')
            if src_ip_condition:
                conditions["network"].append(f'"{src_ip_condition}" in src_ip')
            if dest_port_condition:
                conditions["network"].append(f'"{dest_port_condition}" in dest_port')
            if protocol_condition:
                conditions["network"].append(f'"{protocol_condition}" in protocol')
            if proto_info_condition:
                conditions["network"].append(f'"{proto_info_condition}" in proto_info')
        # System conditions
        if (
            "event_id CONTAINS" in line
            or "event_message CONTAINS" in line
            or "param1" in line
            or "param2" in line
            or "Thread:remote_create" in line
            or "raw_event" in line
            or "log_name ==" in line
            or "event_code ==" in line
            or "object_type ==" in line
            or "subject_security_id !=" in line
            or "[EventCode]" in line
            or "[AuthenticationPackageName]" in line
            or "[Severity]" in line
            or "[LogonType]" in line
        ):
            event_id_condition = None
            event_message_condition = None
            raw_event_condition = None
            log_name_condition = None
            event_code_condition = None
            object_type_condition = None
            subject_security_id_condition = None
            auth_package_condition = None
            severity_condition = None
            logon_type_condition = None
            param1_condition = None
            param2_condition = None

            if "param1 in" in line:
                param1_condition = (
                    line.split("param1 in")[1]
                    .strip()
                    .strip(" []*")
                    .replace('"', "")
                    .split(",")
                )
            if "param2 ==" in line:
                param2_condition = (
                    line.split("param2 ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "log_name ==" in line:
                log_name_condition = (
                    line.split("log_name ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "event_code ==" in line:
                event_code_condition = (
                    line.split("event_code ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "[EventCode] " in line:
                event_code_condition = (
                    line.split("==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "object_type ==" in line:
                object_type_condition = (
                    line.split("object_type ==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "subject_security_id !=" in line:
                subject_security_id_condition = (
                    line.split("subject_security_id !=")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "event_id CONTAINS" in line:
                event_id_condition = (
                    line.split("event_id CONTAINS")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "event_message CONTAINS" in line:
                event_message_condition = (
                    line.split("event_message CONTAINS")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "Thread:remote_create" in line:
                raw_event_condition = (
                    line.split("Thread:remote_create")[1]
                    .strip()
                    .strip("()*")
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "[AuthenticationPackageName]" in line:
                auth_package_condition = (
                    line.split("==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "[Severity]" in line:
                severity_condition = (
                    line.split("==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "[LogonType]" in line:
                logon_type_condition = (
                    line.split("==")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if "raw_event" in line:
                raw_event_condition = (
                    line.split("raw_event CONTAINS")[1]
                    .split()[0]
                    .strip('() "*')
                    .replace("*", "")
                    .replace('"', '\\"')
                )
            if param1_condition:
                conditions["system"].append(f'"{param1_condition}" in param1')
            if param2_condition:
                conditions["system"].append(f'"{param2_condition}" in param2')
            if event_id_condition:
                conditions["system"].append(f'"{event_id_condition}" in event_id')
            if event_message_condition:
                conditions["system"].append(
                    f'"{event_message_condition}" in event_message'
                )
            if raw_event_condition:
                conditions["system"].append(f'"{raw_event_condition}" in raw_event')
            if log_name_condition:
                conditions["system"].append(f'"{log_name_condition}" in log_name')
            if event_code_condition:
                conditions["system"].append(f'"{event_code_condition}" in event_code')
            if object_type_condition:
                conditions["system"].append(f'"{object_type_condition}" in object_type')
            if subject_security_id_condition:
                conditions["system"].append(
                    f'"{subject_security_id_condition}" in subject_security_id'
                )
            if auth_package_condition:
                conditions["system"].append(
                    f'"{auth_package_condition}" in auth_package'
                )
            if severity_condition:
                conditions["system"].append(f'"{severity_condition}" in severity')
            if logon_type_condition:
                conditions["system"].append(f'"{logon_type_condition}" in logon_type')

        # Application conditions
        if "app_name CONTAINS" in line or "log_level CONTAINS" in line:
            app_name_condition = None
            log_level_condition = None
            if "app_name CONTAINS" in line:
                app_name_condition = (
                    line.split("app_name CONTAINS")[1].split()[0].strip(' "*')
                )
            if "log_level CONTAINS" in line:
                log_level_condition = (
                    line.split("log_level CONTAINS")[1].split()[0].strip(' "*')
                )
            if app_name_condition:
                conditions["application"].append(f'"{app_name_condition}" in app_name')
            if log_level_condition:
                conditions["application"].append(
                    f'"{log_level_condition}" in log_level'
                )

    debug(f"Extracted conditions: {conditions}")
    return conditions


def read_pseudocode(file_path):
    try:
        with codecs.open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with codecs.open(file_path, "r", encoding="latin-1") as f:
            return f.read()


if __name__ == "__main__":
    for analytic_file in os.listdir(analytics_dir):
        if analytic_file.endswith(".txt"):
            analytic_id = analytic_file.split(".")[0]
            pseudocode = read_pseudocode(os.path.join(analytics_dir, analytic_file))
            generate_script(analytic_id, pseudocode)

    debug_file.close()
