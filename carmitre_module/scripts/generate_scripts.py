import os
import codecs
import re
import logging

base_dir = os.path.join(
    os.path.expanduser("~"),
    "Documents",
    "GitHub",
    "autodiagnostictools",
    "carmitre_module",
)
analytics_dir = os.path.join(base_dir, "analytics")
scripts_dir = os.path.join(base_dir, "scripts", "generated")

if not os.path.exists(scripts_dir):
    os.makedirs(scripts_dir)

# Archivo txt para depuracion
debug_file_path = os.path.join(scripts_dir, "depuracion_resultados.txt")

# Configuracion de logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


# Funcion depuracion para imprimir mensajes en consola y escribir en archivo de depuracion
def debug(message, write_to_file=True):
    print(message)
    if write_to_file:
        with open(debug_file_path, "a") as debug_file:
            debug_file.write(message + "\n")


# Plantilla para definir como se generara el script de la funcion generate_scripts
script_template = """
import json
import os
import re

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
        command_line = process.get("command_line", "")
        exe = process.get("exe", "")
        cmd = process.get("command_line", "")
        image_path = process.get("image_path", "")
        process_path = process.get("process_path", "")
        parent_exe = process.get("parent_exe", "")
        key = process.get("key", "")
        parent_image_path = process.get("parent_image_path", "")
        raw_event = process.get("raw_event", "")
        parent_image = process.get("parent_image", "")
        image = process.get("image", "")
        integrity_level = process.get("integrity_level", "")
        src_ip = process.get("src_ip", "")
        smb_write = process.get("smb_write", "")
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
        proto_info_rpc_interface = log.get("proto_info.rpc", "")
        if {network_conditions}:
            susp_network_logs.append(log)
    return susp_network_logs

def filter_suspicious_system_logs(system_logs):
    susp_system_logs = []
    for system in system_logs:
        event_id = system.get("event_id", "")
        event_message = system.get("event_message", "")
        raw_event = system.get("raw_event", "")
        log_name = system.get("log_name", "")
        event_code = system.get("event_code", "")
        object_type = system.get("object_type", "")
        subject_security_id = system.get("subject_security_id", "")
        event_code = system.get("EventCode", "")
        auth_package = system.get("AuthenticationPackageName", "")
        severity = system.get("Severity", "")
        logon_type = system.get("LogonType", "")
        param1 = system.get("param1", "")
        param2 = system.get("param2", "")
        target_user_name = system.get("target_user_name", "")
        authentication_package_name = system.get("authentication_package_name", "")
        hostname = system.get("hostname", "")
        if {system_conditions}:
            susp_system_logs.append(system)
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
        file_name = log.get("file_name", "")
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

def main():
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

if __name__ == "__main__":
    main()
"""


# Funcion para generar un script a partir de los pseudocodigos
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
    # Escribir el script generado en un archivo
    with codecs.open(
        os.path.join(scripts_dir, f"analyze_{analytic_id}.py"), "w", encoding="utf-8"
    ) as script_file:
        script_file.write(script_content)


def sanitize_value(value):
    """ "
    Sanitiza un valor eliminado de caracteres no deseados y escapando comillas dobles.
    """
    return value.strip().replace('"', '\\"').replace("*", "").replace("\\", "")


def extract_condition(pattern, line, condition_type, field_name):
    """
    Extraer una condicion de una linea de psuedocodigo usando una expresion regular
    :param pattern: Expresion regular para buscar la condicion
    :param line: Linea de pseudocodigo
    :param condition_type: Tipo de condicion (process, registry, network, system, application, service, file)
    :param field_name: Nombre del campo en la condicion
    :return: Tupla con el valor de la condicion y el tipo de condicion
    """
    try:
        match = re.search(pattern, line)
        if match:
            value = sanitize_value(match.group(1))
            logging.info(
                f"Extracted {condition_type} condition:{field_name} == {value}"
            )
            return f'{field_name} == "{value}"'
        return None
    except Exception as e:
        logging.error(f"Error extracting {condition_type} condition: {e}")
        return None


def classify_line(line):
    """
    Clasifica una línea de pseudocódigo para determinar si es de un proceso, un evento del sistema, un registro, una red, un archivo, una aplicación o un servicio.
    """
    # Palabras clave para la clasificación de cada tipo de log
    process_keywords = [
        "exe",
        "command_line",
        "parent_image",
        "image",
        "process_path",
        "src_ip",
        "cmd",
    ]

    system_keywords = [
        "event_id",
        "event_message",
        "log_name",
        "event_code",
        "severity",
        "logon_type",
        "auth_package",
        "raw_event",
        "EventCode",
        "Severity",
        "LogonType",
        "AuthenticationPackageName",
        "target_user_name",
        "authentication_package_name",
        "AuthenticationPackageName",
    ]

    registry_keywords = ["key", "value", "Key"]

    network_keywords = [
        "source_ip",
        "destination_ip",
        "protocol",
        "data",
        "dest_port",
        "src_port",
        "proto_info",
        "port",
        "proto_info.rpc_interface",
    ]
    application_keywords = ["application", "log_level"]

    service_keywords = ["image_path"]

    file_keywords = ["extension", "file_path", "image_path", "file_name"]

    # Clasificar según la presencia de palabras clave específicas
    if any(keyword in line for keyword in process_keywords):
        return "process"
    elif any(keyword in line for keyword in system_keywords):
        return "system"
    elif any(keyword in line for keyword in registry_keywords):
        return "registry"
    elif any(keyword in line for keyword in network_keywords):
        return "network"
    elif any(keyword in line for keyword in application_keywords):
        return "application"
    elif any(keyword in line for keyword in service_keywords):
        return "service"
    elif any(keyword in line for keyword in file_keywords):
        return "file"

    # Por defecto, devolver None si no cumple con ningún criterio
    return None


def extract_process_conditions(line, conditions):
    """
    Extrae condiciones relacionadas con procesos, incluyendo casos con combinaciones de AND y OR.

    :param line: Línea de pseudocódigo
    :param conditions: Diccionario con las condiciones extraídas
    """

    # Extraer múltiples condiciones de command_line

    command_line_conditions = re.findall(
        r'command_line\s*CONTAINS\s*\("([\w\*\(\)\s]+)"\)', line
    )
    and_conditions = re.findall(
        r'command_line\s*CONTAINS\s*\("([\w\*\(\)\s]+)"\)\s*AND\s*command_line\s*CONTAINS\s*\("([\w\*\(\)\s]+)"\)',
        line,
    )
    or_conditions = re.findall(
        r'command_line\s*CONTAINS\s*\("([\w\*\(\)\s]+)"\)\s*OR\s*command_line\s*CONTAINS\s*\("([\w\*\(\)\s]+)"\)',
        line,
    )

    for condition in command_line_conditions:
        conditions["process"].append(f'"{condition}" in command_line')

    # Manejo de condiciones conectadas con OR
    for condition1, condition2 in or_conditions:
        conditions["process"].append(
            f'("{condition1}" in command_line or "{condition2}" in command_line)'
        )

    # Manejo de condiciones conectadas con AND
    for condition1, condition2 in and_conditions:
        conditions["process"].append(
            f'("{condition1}" in command_line and "{condition2}" in command_line)'
        )

    exe_command_conditions = re.findall(
        r'exe\s*=\s*["”“]([A-Za-z]:\\[\w\\\.]+)["”“]\s*AND\s*command_line\s*=\s*\*([\w\s\-\*]+)\*',
        line,
    )
    for exe_value, command in exe_command_conditions:
        conditions["process"].append(
            f'(exe == r"{exe_value}") and ("{command}" in command_line)'
        )
    exe_command_conditions = re.findall(
        r'exe\s*=\s*["”“](C:\\Windows\\System32\\certutil.exe)["”“]\s*AND\s*command_line\s*=\s*["”“]\*([\w\-\*]+)\*["”“]',
        line,
    )
    for exe_value, command in exe_command_conditions:
        conditions["process"].append(
            f'(exe == r"{exe_value}") and ("{command}" in command_line)'
        )

    # Manejo de condiciones con lista de "one of"
    one_of_conditions = re.findall(
        r"command_line\s*includes\s*one\s*of\s*\[([\w\*\(\)\,\s]+)\]", line
    )
    for one_of in one_of_conditions:
        values = one_of.split(",")
        or_clauses = " or ".join([f'"{val.strip()}" in command_line' for val in values])
        conditions["process"].append(f"({or_clauses})")

    # Manejo de condiciones con bcdedit.exe
    bcdedit_conditions = re.findall(
        r'exe\s*=\s*["”“](C:\\Windows\\System32\\bcdedit.exe)["”“]\s*AND\s*command_line\s*=\s*["”“]\*([\w\*]+)\*["”“]',
        line,
    )
    for exe_value, command in bcdedit_conditions:
        conditions["process"].append(
            f'(exe == r"{exe_value}") and ("{command}" in command_line)'
        )

    cmd_conditions = re.findall(
        r'parent_image_path\s*==\s*"([\w\\:]+)"\s*AND\s*image_path\s*==\s*"([\w\\:]+)"\s*AND\s*command_line\s*==\s*"(\*[\w\*\(\)\\]+)"\s*AND\s*command_line\s*==\s*"(\*[\w\*\(\)\\]+)"',
        line,
    )

    for parent_image, img_path, cmd1, cmd2 in cmd_conditions:
        conditions["process"].append(
            f'(parent_image_path == r"{parent_image}" and image_path == r"{img_path}" and '
            f'"{cmd1}" in command_line and "{cmd2}" in command_line)'
        )

    # Condición para rundll32.exe con command_line específico
    rundll_conditions = re.findall(
        r'image_path\s*==\s*"([\w\\:]+)"\s*AND\s*command_line\s*==\s*"([\w\s\*\/\,\:\-]+)"',
        line,
    )

    for img_path, cmd in rundll_conditions:
        conditions["process"].append(
            f'(image_path == r"{img_path}" and "{cmd}" in command_line)'
        )

    parent_image_conditions = re.findall(
        r'parent_image\s*=\s*"(\*[\w]+\.\w+)"\s*OR\s*parent_image\s*=\s*"(\*[\w]+\.\w+)"\s*OR\s*parent_image\s*=\s*"(\*[\w]+\.\w+)"',
        line,
    )
    for parent1, parent2, parent3 in parent_image_conditions:
        conditions["process"].append(
            f'(parent_image == "{parent1}" or parent_image == "{parent2}" or parent_image == "{parent3}")'
        )

    # Manejo de condiciones para image.exe
    image_conditions = re.findall(r'image\s*=\s*"(\*[\w]+\.\w+)"', line)
    for img in image_conditions:
        conditions["process"].append(f'image == "{img}"')

    if 'parent_image = "C:\\Windows\\System32\\cmd.exe' in line:
        if (
            "command_line = reg.exe%HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System%REG_DWORD /d 0%"
            in line
        ):
            conditions["process"].append(
                '(parent_image == r"C:\\Windows\\System32\\cmd.exe") AND '
                '(command_line == "reg.exe%HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System%REG_DWORD /d 0%")'
            )

    if "exe = C:\\Windows\\System32\\sc.exe" in line:
        if (
            'command_line="sc *config*" OR command_line="sc *stop*" OR command_line="sc *query*"'
            in line
        ):
            conditions["process"].append(
                '(exe == r"C:\\Windows\\System32\\sc.exe") AND '
                '(command_line == "sc *config*" OR command_line == "sc *stop*" OR command_line == "sc *query*")'
            )

    # Condición específica para exe y command_line
    if (
        "exe = C:\\Windows\\System32\\net.exe" in line
        and "exe = C:\\Windows\\System32\\net1.exe" in line
    ):
        # Buscando los valores de command_line
        if (
            "command_line = *localgroup*" in line
            or "command_line = */add*" in line
            or "command_line = *user*" in line
        ):
            conditions["process"].append(
                '(exe == r"C:\\Windows\\System32\\net.exe" or exe == r"C:\\Windows\\System32\\net1.exe") '
                'and ("localgroup" in command_line or "/add" in command_line or "user" in command_line)'
            )
    # Condicion para lsass en eventos remotos
    lsass_remote_conditions = re.findall(r'"lsass" in raw event', line)
    for condition in lsass_remote_conditions:
        conditions["process"].append(f'"lsass" in raw_event')

        # Bandera para indicar si hemos encontrado la condición parcial para CMSTP.exe
    cmstp_partial_match = False

    # Verificar la línea actual para la condición parcial
    if 'exe="C:\\Windows\\System32\\CMSTP.exe" AND' in line:
        if "src_ip NOT IN [10.0.0.0/8,192.168.0.0/16, 172.16.0.0/12]" in line:
            conditions["process"].append(
                '(exe == r"C:\\Windows\\System32\\CMSTP.exe") AND '
                '(src_ip NOT IN ["10.0.0.0/8","192.168.0.0/16", "172.16.0.0/12"])'
            )

    exe_or_conditions = re.findall(
        r'exe\s*=\s*"([^"]+)"\s*OR\s*exe\s*=\s*"([^"]+)"', line
    )
    for exe1, exe2 in exe_or_conditions:
        conditions["process"].append(f'(exe == r"{exe1}" or exe == r"{exe2}")')

    # Inicializar variables para las condiciones
    current_exe_condition = None
    current_command_conditions = []
    or_conditions = []

    # Verificar si la línea contiene una condición de exe
    if "exe=" in line:
        exe_match = re.search(r'exe\s*=\s*"([^"]+)"', line)
        if exe_match:
            current_exe_condition = f'exe == r"{exe_match.group(1)}"'

    # Verificar si la línea contiene una condición de command_line
    if "command_line=" in line:
        cmd_match = re.search(r'command_line\s*=\s*"(\*[\w\s\-]+)"', line)
        if cmd_match:
            current_command_conditions.append(f'"{cmd_match.group(1)}" in command_line')

    # Buscar condiciones adicionales con "OR"
    or_conditions = re.findall(
        r'command_line\s*=\s*"(\*Remove\-SmbShare\*|\*Remove\-FileShare\*)"', line
    )
    for or_cond in or_conditions:
        current_command_conditions.append(f'"{or_cond}" in command_line')

    # Combinación de las condiciones acumuladas
    if current_exe_condition or current_command_conditions:
        combined_conditions = []
        if current_exe_condition:
            combined_conditions.append(current_exe_condition)
        if current_command_conditions:
            combined_conditions.append(" or ".join(current_command_conditions))

        # Si hay condiciones combinadas, agregarlas
        if combined_conditions:
            conditions["process"].append(f'({" and ".join(combined_conditions)})')

        # Manejo de condiciones conectadas con OR para command_line
    command_line_or_conditions = re.findall(
        r'command_line\s*=\s*"([^"]+)"\s*OR\s*command_line\s*=\s*"([^"]+)"', line
    )
    for cmd1, cmd2 in command_line_or_conditions:
        conditions["process"].append(
            f'("{cmd1}" in command_line or "{cmd2}" in command_line)'
        )

    # Caso específico para múltiples OR en command_line
    multiple_command_or_conditions = re.findall(
        r'command_line\s*=\s*"([^"]+)"(?:\s*OR\s*command_line\s*=\s*"([^"]+)")+', line
    )
    for condition in multiple_command_or_conditions:
        cmd_or_conditions = " or ".join(
            [f'"{cmd}" in command_line' for cmd in condition if cmd]
        )
        conditions["process"].append(f"({cmd_or_conditions})")

    # car-2020-11-003
    # Manejo de condiciones con exe, image y command_line conectados con OR
    mavinject_conditions = re.findall(
        r'exe\s*=\s*"([^"]+)"\s*OR\s*Image\s*=\s*"([^"]+)"\s*OR\s*command_line\s*=\s*"([^"]+)"',
        line,
    )

    for exe_value, img_value, cmd_value in mavinject_conditions:
        conditions["process"].append(
            f'(exe == r"{exe_value}" or image == r"{img_value}" or "{cmd_value}" in command_line)'
        )
    # CAR-2020-11-002
    # Manejo de condiciones con exe conectadas con OR
    sniffer_conditions = re.findall(
        r'exe\s*=\s*"([^"]+)"\s*OR|exe\s*=\s*"([^"]+)"\s*OR|exe\s*=\s*"([^"]+)"\s*OR|exe\s*=\s*"([^"]+)"\s*OR|exe\s*=\s*"([^"]+)"',
        line,
    )
    for cond in sniffer_conditions:
        conditions["process"].append(f'(exe == r"{cond}")')

    # Condición para logman.exe con parent_exe específico
    logman_conditions = re.findall(
        r'exe\s*=\s*"logman.exe"\s*AND\s*parent_exe\s*exists\s*AND\s*parent_exe\s*!=\s*"([^"]+)"',
        line,
    )
    for parent_exe_value in logman_conditions:
        conditions["process"].append(
            f'(exe == "logman.exe" and parent_exe and parent_exe != r"{parent_exe_value}")'
        )
    # CAR-2020-11-001
    # Manejo de condiciones con command_line para logon_script_key_processes
    logon_script_conditions = re.findall(r'command_line\s*=\s*"([^"]+)"', line)
    for command in logon_script_conditions:
        conditions["process"].append(f'"{command}" in command_line')

    # Manejo de condiciones de registro con key para registry_logon_key_events
    logon_key_conditions = re.findall(r'key\s*=\s*"([^"]+)"', line)
    for key_value in logon_key_conditions:
        conditions["registry"].append(f'key == r"{key_value}"')
    # CAR-2020-08-002
    # Condiciones específicas para exe conectadas con OR y regex para command_line
    exe_conditions = re.findall(
        r'exe\s*==\s*"([^"]+)"(?:\s*OR\s*exe\s*==\s*"([^"]+)")*', line
    )

    # Extraer condición de regex para command_line
    regex_condition = re.search(r'command_line\.matches\("([^"]+)"\)', line)

    # Construir lista de condiciones para exe
    exe_list = [exe for group in exe_conditions for exe in group if exe]
    exe_condition_str = " or ".join([f'exe == "{exe}"' for exe in exe_list])

    # Agregar la condición de exe al diccionario de condiciones si está presente
    if exe_condition_str:
        conditions["process"].append(f"({exe_condition_str})")

    # Agregar la condición de regex para command_line si está presente
    if regex_condition:
        regex_str = f're.match(r"{regex_condition.group(1)}", command_line)'
        conditions["process"].append(regex_str)

    # Si ambas condiciones están presentes, combinarlas con AND
    if exe_condition_str and regex_condition:
        combined_condition = f"({exe_condition_str}) and {regex_str}"
        # Reemplazar las condiciones separadas por la condición combinada
        conditions["process"] = [combined_condition]
    # car-2019-04-003
    if (
        'image_path == "*regsvr32.exe"' in line
        and 'command_line == "*scrobj.dll"' in line
    ):
        combined_condition = (
            '(image_path == "*regsvr32.exe" and command_line == "*scrobj.dll")'
        )
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)
        return
    # CAR-2019-04-003Ç
    if (
        'parent_image_path == "*regsvr32.exe"' in line
        and 'image_path != "*regsvr32.exe*"' in line
    ):
        combined_condition = (
            '(parent_image_path == "*regsvr32.exe" and image_path != "*regsvr32.exe*")'
        )
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)
        return
    # CAR-2019-04-001
    if 'integrity_level == "High"' in line:
        combined_condition = (
            '(integrity_level == "High" and '
            '(parent_image_path == r"c:\\windows\\system32\\fodhelper.exe" or '
            '"*.exe\\"*cleanmgr.exe /autoclean*" in command_line or '
            'image_path == r"c:\\program files\\windows media player\\osk.exe" or '
            'parent_image_path == r"c:\\windows\\system32\\slui.exe" or '
            '(parent_command_line == r"\\"c:\\windows\\system32\\dism.exe\\"\\"*.xml\\"" and '
            'image_path != r"c:\\users\\*\\appdata\\local\\temp\\*\\dismhost.exe") or '
            '(command_line == r"\\"c:\\windows\\system32\\wusa.exe\\"*/quiet*" and '
            'user != "NOT_TRANSLATED" and '
            'current_working_directory == r"c:\\windows\\system32\\" and '
            'parent_image_path != r"c:\\windows\\explorer.exe") or '
            '(parent_image_path == r"c:\\windows\\*dccw.exe" and '
            'image_path != r"c:\\windows\\system32\\cttune.exe")))'
        )
        conditions["process"].append(combined_condition)
        return
    # CAR-2016-03-002
    if 'exe == "wmic.exe"' in line and "command_line" in line:
        # Construimos la condición combinada específica
        combined_condition = '(exe == "wmic.exe" and "process call create" in command_line and "/node:" in command_line)'
        # Aseguramos que sea la única condición en la lista
        conditions["process"] = [combined_condition]
        return
    # CAR-2014-11-008
    if 'parent_exe == "winlogon.exe"' in line and 'exe == "cmd.exe"' in line:
        combined_condition = '(parent_exe == "winlogon.exe" and exe == "cmd.exe")'
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)
        return
    # CAR-2014-11-003
    if "(sethcutilmanosknarratormagnify)\.exe" in line:
        combined_condition = '(command_line == "sethcutilmanosknarratormagnify.exe")'
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)

    # Car-2014-11-002
    cmd_exe_condition = None
    historic_condition = None
    current_condition = None
    if 'exe == "cmd.exe"' in line:
        cmd_exe_condition = 'exe == "cmd.exe"'

    if "timestamp < now - 1 day" in line and "timestamp > now - 1 day" in line:
        historic_condition = "timestamp < now - 1 day AND timestamp > now - 1 day"

    if "timestamp >= now - 1 day" in line:
        current_condition = "timestamp >= now - 1 day"

    # Verificamos si todas las condiciones están presentes para combinarlas
    if cmd_exe_condition and historic_condition and current_condition:
        combined_condition = f"({cmd_exe_condition} AND {historic_condition} AND {current_condition} AND historic_cmd - current_cmd)"
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)

    # Car-2014-05-002
    if 'exe == "cmd.exe"' in line and 'parent_exe == "services.exe"' in line:
        combined_condition = '(exe == "cmd.exe" and parent_exe == "services.exe")'
        conditions["process"] = [
            combined_condition
        ]  # Sobreescribimos la lista para asegurarnos de que solo incluya esta condición
        print(f"combined_condition: {combined_condition}")
        return
    # CAR-2014-04-003
    if 'exe == "powershell.exe"' in line and 'parent_exe != "explorer.exe"' in line:
        combined_condition = (
            '(exe == "powershell.exe" and parent_exe != "explorer.exe")'
        )
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return

    # CAR-2013-07-005
    if 'command_line == "* a *"' in line:
        combined_condition = '(command_line == "* a *")'
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return

    # cAR-2013-07-001
    if "-R .* -pw" in line:
        combined_condition_port_fwd = '(command_line.match("-R .* -pw"))'
        if combined_condition_port_fwd not in conditions["process"]:
            conditions["process"].append(combined_condition_port_fwd)

    # Patrón para -pw .* .* .*@.* (scp)
    if "-pw .* .* .*@.*" in line:
        combined_condition_scp = '(command_line.match("-pw .* .* .*@.*"))'
        if combined_condition_scp not in conditions["process"]:
            conditions["process"].append(combined_condition_scp)

    # Patrón para sekurlsa (Mimikatz)
    if "sekurlsa" in line:
        combined_condition_mimikatz = '(command_line.match("sekurlsa"))'
        if combined_condition_mimikatz not in conditions["process"]:
            conditions["process"].append(combined_condition_mimikatz)

    # Patrón para -hp (RAR)
    if "-hp" in line:
        combined_condition_rar = '(command_line.match("-hp"))'
        if combined_condition_rar not in conditions["process"]:
            conditions["process"].append(combined_condition_rar)

    # Patrón para .* a .* (Archivo)
    if ".* a .*" in line:
        combined_condition_archive = '(command_line.match(".* a .*"))'
        if combined_condition_archive not in conditions["process"]:
            conditions["process"].append(combined_condition_archive)

    # Patrón para dirección IP (IPv4)
    if r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" in line:
        combined_condition_ip_addr = (
            '(command_line.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))'
        )
        if combined_condition_ip_addr not in conditions["process"]:
            conditions["process"].append(combined_condition_ip_addr)

    # Car-2013-05-005
    if "smb_write" in line and "process" in line:
        join_condition = (
            "(smb_write.hostname == process.hostname and "
            "smb_write.file_path == process.image_path and "
            "smb_write.time < process.time)"
        )
        if join_condition not in conditions["process"]:
            conditions["process"].append(join_condition)
        print(f"join_condition: {join_condition}")
    # Car-2013-05-002
    suspicious_paths = re.findall(
        r'image_path\s*==\s*"([\w\\:\*%]+)"\s*or\s*image_path\s*==\s*"([\w\\:\*%]+)"',
        line,
    )

    for path1, path2 in suspicious_paths:
        combined_condition = (
            f'(image_path.startswith(r"{path1}") or image_path.startswith(r"{path2}"))'
        )
        if combined_condition not in conditions["process"]:
            conditions["process"].append(combined_condition)

    # Condiciones adicionales
    image_path = extract_condition(
        r'image_path\s*==\s*"([\w\\:\*%]+)"', line, "process", "image_path"
    )
    if image_path:
        conditions["process"].append(image_path)

    # Otras condiciones relacionadas con procesos
    exe = extract_condition(
        r'exe\s*=\s*["”“]?([\w\*\(\)\s]+)["”“]?', line, "process", "exe"
    )
    exe = extract_condition(r'exe\s*=\s*"([\w\*\(\)\s"]+)"', line, "process", "exe")
    exe = extract_condition(r'exe\s*==\s*"([\w\\:\*\.\s]+)"', line, "process", "exe")
    parent_exe = extract_condition(
        r'parent_exe\s*==\s*"([\w\*\(\)\s"]+)"', line, "process", "parent_exe"
    )
    image_path = extract_condition(
        r'image_path\s*==\s*"([\w\*\(\)\s"]+)"', line, "process", "image_path"
    )
    process_path = extract_condition(
        r'process_path\s*==\s*"([\w\*\(\)\s"]+)"', line, "process", "process_path"
    )
    parent_image_path = extract_condition(
        r'parent_image_path\s*==\s*"([\w\*\(\)\s"]+)"',
        line,
        "process",
        "parent_image_path",
    )
    key = extract_condition(r'key\s*==\s*"([\w\*\(\)\s"]+)"', line, "process", "key")
    parent_image = extract_condition(
        r'parent_image\s*=\s*"([\w\\:]+)"', line, "process", "parent_image"
    )
    src_ip = extract_condition(
        r"src_ip\s*NOT\s*IN\s*\[([\d\.,/]+)\]", line, "process", "src_ip"
    )
    integrity_level = extract_condition(
        r'integrity_level\s*==\s*"([\w\*\(\)\s"]+)"', line, "process", "integrity_level"
    )

    if exe:
        conditions["process"].append(exe)
    if parent_exe:
        conditions["process"].append(parent_exe)
    if image_path:
        conditions["process"].append(image_path)
    if process_path:
        conditions["process"].append(process_path)
    if parent_image_path:
        conditions["process"].append(parent_image_path)
    if key:
        conditions["process"].append(key)
    if parent_image:
        conditions["process"].append(parent_image)
    if integrity_level:
        conditions["process"].append(integrity_level)


def extract_file_conditions(line, conditions):
    # Variables para almacenar temporalmente las condiciones detectadas

    # Extraer las condiciones mejoradas para file_path, image_path y extension
    file_name = extract_condition(
        r'file_name\s*=\s*["”“]?([\w\\:\*\.\s]+)["”“]?', line, "file", "file_name"
    )
    file_path = extract_condition(
        r'file_path\s*=\s*["”“]?([\w\\:\*\.\s]+)["”“]?', line, "file", "file_path"
    )
    image_path = extract_condition(
        r'image_path\s*!=\s*["”“]?([\w\\:\*\.\s]+)["”“]?', line, "file", "image_path"
    )
    extension = extract_condition(
        r'extension\s*=\s*["”“]?([\w\.]+)["”“]?', line, "file", "extension"
    )
    # Comprobación específica para ntds.dit

    # Comprobación específica para ntds.dit
    if "ntds.dit" in line:
        # Agregar manualmente la condición combinada para file_name e image_path
        combined_condition = (
            '(file_name == "ntds.dit" and image_path == "*ntdsutil.exe")'
        )
        if combined_condition not in conditions["file"]:
            conditions["file"].append(combined_condition)
        return  # Salir de la función ya que se ha manejado el caso específico
    if "lsass*.dmp" in line:
        combined_condition = '(file_name == "lsass*.dmp" and image_path == "C:\\Windows\\*\\taskmgr.exe")'
        if combined_condition not in conditions["file"]:
            conditions["file"].append(combined_condition)
        return

    # Formatear correctamente las condiciones de file_path e image_path sin etiquetas adicionales
    if file_path:
        conditions["file"].append(file_path)
    if image_path:
        conditions["file"].append(image_path)
    if extension:
        conditions["file"].append(extension)
    if file_name:
        conditions["file"].append(file_name)

    # Nueva condición combinada: extensión y file_path
    extension_and_file_path = re.findall(
        r'extension\s*=\s*["”“]?([\w\.]+)["”“]?\s*AND\s*file_path\s*=\s*["”“]?([\w\\\:\*\.\s]+)["”“]?',
        line,
    )
    for ext, path in extension_and_file_path:
        conditions["file"].append(
            f'(extension == "{ext}" and file_path.startswith(r"{path}"))'
        )


def extract_registry_conditions(line, conditions):

    key_match = re.search(r'Key\s*=\s*"([^"]+)"', line)
    value_match = re.findall(
        r'value\s*=\s*"([^"]+)"', line
    )  # Captura múltiples valores de 'value'

    if key_match:
        key_condition = f'key == "{sanitize_value(key_match.group(1))}"'
    else:
        key_condition = None

    # Manejar múltiples valores de 'value' con "OR"
    if value_match:
        value_conditions = " or ".join(
            [f'value == "{sanitize_value(value)}"' for value in value_match]
        )
    else:
        value_conditions = None
    if (
        r'key="*\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\SCRNSAVE.EXE"'
        in line
    ):
        scr_screensave_condition = 'key == r"*\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop\\SCRNSAVE.EXE"'
        conditions["registry"].append(scr_screensave_condition)

    # Verificar si hay condiciones de 'Key' y 'value', y combinarlas con "AND"
    if key_condition and value_conditions:
        combined_condition = f"({key_condition}) and ({value_conditions})"
        conditions["registry"].append(combined_condition)
    elif key_condition:
        conditions["registry"].append(key_condition)
    elif value_conditions:
        conditions["registry"].append(value_conditions)


def extract_network_conditions(line, conditions):

    src_ip = extract_condition(
        r'source_ip\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "network", "source_ip"
    )
    dest_port = extract_condition(
        r'dest_port\s*==\s*([\w\*\(\)\s"]+)', line, "network", "dest_port"
    )
    protocol = extract_condition(
        r'protocol\s*==\s*([\w\*\(\)\s"]+)', line, "network", "protocol"
    )
    proto_info = extract_condition(
        r'proto_info\s*==\s*([\w\*\(\)\s"]+)', line, "network", "proto_info"
    )
    dest_port = extract_condition(
        r'dest_port\s*>=\s*([\w\*\(\)\s"]+)', line, "network", "dest_port"
    )
    src_port = extract_condition(
        r'src_port\s*>=\s*([\w\*\(\)\s"]+)', line, "network", "src_port"
    )
    port = extract_condition(r'port\s*==\s*([\w\*\(\)\s"]+)', line, "network", "port")
    proto_info_rpc_interface = extract_condition(
        r'proto_info\.rpc_interface\s*==\s*["”“]?([\w\*\(\)\s]+)["”“]?',
        line,
        "network",
        "proto_info",
    )
    if (
        "src_port >= 49152" in line
        and "dest_port >= 49152" in line
        and 'proto_info.rpc_interface == "ITaskSchedulerService"' in line
    ):
        combined_condition = '(src_port >= 49152 and dest_port >= 49152 and proto_info.rpc_interface == "ITaskSchedulerService")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        return

    # car-2015-04-001
    if "dest_port == 445" in line and 'proto_info.pipe == "ATSVC"' in line:
        combined_condition = '(dest_port == 445 and proto_info.pipe == "ATSVC")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        return
    if 'proto_info.function == "JobAdd"' in line:
        combined_condition = '(proto_info.function == "JobAdd")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        return

    # car2014-12-001
    # Depurar condiciones combinadas específicas
    if (
        "dest_port >= 49152" in line
        and 'proto_info.rpc_interface == "IRemUnknown2"' in line
    ):
        combined_condition = '(src_port >= 49152 and dest_port >= 49152 and proto_info.rpc_interface == "IRemUnknown2")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return
    # Manejo de la condición de join
    if (
        "wmi_flow.time < wmi_children.time < wmi_flow.time + 1sec" in line
        and "wmi_flow.hostname == wmi_children.hostname" in line
    ):
        join_condition = "(wmi_flow.time < wmi_children.time < wmi_flow.time + 1 and wmi_flow.hostname == wmi_children.hostname)"
        if join_condition not in conditions["network"]:
            conditions["network"].append(join_condition)
        print(f"join_condition: {join_condition}")
    # CAR-2014-11-007
    if (
        "dest_port == 135" in line
        and 'proto_info.rpc_interface == "IRemUnknown2"' in line
    ):
        combined_condition = (
            '(dest_port == 135 and proto_info.rpc_interface == "IRemUnknown2")'
        )
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition (CAR-2014-11-007): {combined_condition}")
        return
    # CAR-2014-11-005
    if "dest_port == 445" in line and 'proto_info.pipe == "WINREG"' in line:
        combined_condition = '(dest_port == 445 and proto_info.pipe == "WINREG")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition (CAR-2014-11-005 - WINREG): {combined_condition}")
        return  # Evitar procesar más si esta condición ya se ha manejado

    # Condición para proto_info.function == "Create*" o "SetValue*"
    if (
        'proto_info.function == "Create*"' in line
        or 'proto_info.function == "SetValue*"' in line
    ):
        function_condition = (
            '(proto_info.function == "Create*" or proto_info.function == "SetValue*")'
        )
        if function_condition not in conditions["network"]:
            conditions["network"].append(function_condition)
        print(
            f"function_condition (CAR-2014-11-005 - Create/SetValue): {function_condition}"
        )
        return
    # CAR-2014-03-001
    if 'dest_port == "445"' in line and 'protocol == "smb.write_pipe"' in line:
        combined_condition = '(dest_port == 445 and protocol == "smb.write_pipe")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return

    # Car-2013-09-003
    if "dest_port == 445" in line and "protocol == smb.setup" in line:
        combined_condition = '(dest_port == 445 and protocol == "smb.setup")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return
    # CAR-2013-07-002
    if 'port == "3389"' in line:
        combined_condition = (
            "(port == 3389)"  # Ajustamos el formato correcto para el puerto
        )
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        print(f"combined_condition: {combined_condition}")
        return
    # Car-2013-05-003
    if 'dest_port == "445"' in line and 'protocol == "smb.write"' in line:
        combined_condition = '(dest_port == 445 and protocol == "smb.write")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        return
    # CAR-2013-01-003
    if 'dest_port == "445"' in line and 'protocol == "smb"' in line:
        combined_condition = '(dest_port == "445" and protocol == "smb")'
        if combined_condition not in conditions["network"]:
            conditions["network"].append(combined_condition)
        return

    if proto_info_rpc_interface:
        conditions["network"].append(proto_info_rpc_interface)
    if src_ip:
        conditions["network"].append(src_ip)
    if dest_port:
        conditions["network"].append(dest_port)
    if protocol:
        conditions["network"].append(protocol)
    if proto_info:
        conditions["network"].append(proto_info)
    if src_port:
        conditions["network"].append(src_port)
    if port:
        conditions["network"].append(port)


def extract_system_conditions(line, conditions):

    if (
        'log_name == "Security"' in line
        or 'event_code == "4670"' in line
        or 'object_type == "File"' in line
        or 'subject_security_id != "NT AUTHORITY\\SYSTEM"' in line
    ):
        # Construimos la condición combinada manualmente
        combined_condition = '(log_name == "Security" and event_code == "4670" and object_type == "File" and subject_security_id != "NT AUTHORITY\\SYSTEM")'
        if combined_condition not in conditions["system"]:
            conditions["system"].append(combined_condition)
        return
    if "EventCode == 4624" in line:
        combined_condition = '(event_code == "4624" and target_user_name != "ANONYMOUS LOGON" and authentication_package_name == "NTLM")'
        if combined_condition not in conditions["system"]:
            conditions["system"].append(combined_condition)
        return

    event_id = extract_condition(
        r'event_id\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "system", "event_id"
    )
    event_message = extract_condition(
        r'event_message\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "system", "event_message"
    )
    raw_event = extract_condition(
        r'raw_event\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "system", "raw_event"
    )
    log_name = extract_condition(
        r'log_name\s*==\s*([\w\*\(\)\s"]+)', line, "system", "log_name"
    )
    event_code = extract_condition(
        r'event_code\s*==\s*([\w\*\(\)\s"]+)', line, "system", "event_code"
    )
    object_type = extract_condition(
        r'object_type\s*==\s*([\w\*\(\)\s"]+)', line, "system", "object_type"
    )
    subject_security_id = extract_condition(
        r'subject_security_id\s*!=\s*([\w\*\(\)\s"]+)',
        line,
        "system",
        "subject_security_id",
    )
    event_code = extract_condition(
        r'\[EventCode\]\s*==\s*([\w\*\(\)\s"]+)', line, "system", "event_code"
    )
    auth_package = extract_condition(
        r'\[AuthenticationPackageName\]\s*==\s*([\w\*\(\)\s"]+)',
        line,
        "system",
        "auth_package",
    )
    severity = extract_condition(
        r'\[Severity\]\s*==\s*([\w\*\(\)\s"]+)', line, "system", "severity"
    )
    logon_type = extract_condition(
        r'\[LogonType\]\s*==\s*([\w\*\(\)\s"]+)', line, "system", "logon_type"
    )
    param1 = extract_condition(
        r'param1\s*in\s*\[([\w\*\(\)\s",]+)\]', line, "system", "param1"
    )
    param2 = extract_condition(
        r'param2\s*==\s*([\w\*\(\)\s"]+)', line, "system", "param2"
    )
    target_user_name = extract_condition(
        r'target_user_name\s*!=\s*([\w\*\(\)\s"]+)', line, "system", "target_user_name"
    )
    authentication_package_name = extract_condition(
        r'authentication_package_name\s*==\s*([\w\*\(\)\s"]+)',
        line,
        "system",
        "authentication_package_name",
    )
    hostname = extract_condition(
        r'hostname\s*==\s*([\w\*\(\)\s"]+)', line, "system", "hostname"
    )

    if target_user_name and authentication_package_name:
        combined_condition = f"({target_user_name} and {authentication_package_name})"
        conditions["system"].append(combined_condition)
        return
    if "[EventCode] == 4624" in line:
        # Construimos la condición combinada específica
        combined_condition = '(event_code == "4624" and authentication_package_name == "Negotiate" and severity == "Information" and logon_type == 10)'
        # Aseguramos que sea la única condición en la lista
        conditions["system"] = [combined_condition]
        return
    if 'log_name == "System"' in line:
        # Construimos la condición combinada específica
        combined_condition = '(log_name == "System" and event_code == "7036" and param1 in ["Windows Defender", "Windows Firewall"] and param2 == "stopped")'
        # Aseguramos que sea la única condición en la lista
        conditions["system"] = [combined_condition]
        return
    if '[log_name] == "Security"' in line or '[log_name] == "System"' in line:
        # Construimos la condición combinada específica
        combined_condition = '((log_name == "Security" and event_code in [1100, 1102, 1104]) or (log_name == "System" and event_code == 104))'
        # Aseguramos que sea la única condición en la lista
        conditions["system"] = [combined_condition]
        return

    if event_id:
        conditions["system"].append(event_id)
    if event_message:
        conditions["system"].append(event_message)
    if raw_event:
        conditions["system"].append(raw_event)
    if log_name:
        conditions["system"].append(log_name)
    if event_code:
        conditions["system"].append(event_code)
    if object_type:
        conditions["system"].append(object_type)
    if subject_security_id:
        conditions["system"].append(subject_security_id)
    if auth_package:
        conditions["system"].append(auth_package)
    if severity:
        conditions["system"].append(severity)
    if logon_type:
        conditions["system"].append(logon_type)
    if param1:
        conditions["system"].append(param1)
    if param2:
        conditions["system"].append(param2)
    if hostname:
        conditions["system"].append(hostname)


def extract_application_conditions(line, conditions):
    app_name = extract_condition(
        r'application\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "application", "application"
    )
    log_level = extract_condition(
        r'log_level\s*CONTAINS\s*([\w\*\(\)\s"]+)', line, "application", "log_level"
    )

    if app_name:
        conditions["application"].append(app_name)
    if log_level:
        conditions["application"].append(log_level)


def extract_service_conditions(line, conditions):
    """
    Extrae condiciones relacionadas con servicios
    :param line: Línea de pseudocódigo
    :param conditions: Diccionario con las condiciones extraídas
    """
    # Capturar la condición de image_path que debe coincidir
    image_path_include_match = re.search(r'image_path\s*=\s*"([^"]+)"', line)
    if image_path_include_match:
        image_path_include_pattern = image_path_include_match.group(1)
        # Convertir el patrón a una condición que verifique si termina en .exe
        if (
            image_path_include_pattern == "*\\.exe"
            or image_path_include_pattern.endswith(".exe")
        ):
            image_path_include = 'image_path.endswith(".exe")'
        else:
            image_path_include = f'image_path == "{image_path_include_pattern}"'
    else:
        image_path_include = None

    # Capturar exclusiones de image_path
    image_path_exclude_match = re.search(
        r"image_path\s*does not contain\s*\[([^\]]+)\]", line
    )
    if image_path_exclude_match:
        excludes_str = image_path_exclude_match.group(1)
        # Dividir la cadena en rutas individuales y limpiar comillas, espacios, y eliminar '*'
        excludes = [
            exclude.strip().strip('"').replace("*", "")
            for exclude in excludes_str.split(",")
        ]
        exclude_conditions = [f'"{exclude}" not in image_path' for exclude in excludes]
        image_path_exclude = " and ".join(exclude_conditions)
    else:
        image_path_exclude = None

    # Combinar las condiciones de inclusión y exclusión
    combined_conditions = []
    if image_path_include:
        combined_conditions.append(image_path_include)
    if image_path_exclude:
        combined_conditions.append(image_path_exclude)

    # Unir las condiciones finales y agregarlas al diccionario
    if combined_conditions:
        final_condition = " and ".join(combined_conditions)
        conditions["service"].append(final_condition)


def extract_conditions(pseudocode):
    """
    Funcion principal para extraer condiciones de diferentes tipos de logs de seguridad
    :param pseudocode: Pseudocodigo con las condiciones
    :return: Diccionario con las condiciones extraidas
    """
    conditions = {
        "process": [],
        "registry": [],
        "network": [],
        "system": [],
        "application": [],
        "service": [],
        "file": [],
    }
    for line in pseudocode.splitlines():
        classification = classify_line(line)

        if classification == "process":
            extract_process_conditions(line, conditions)
        elif classification == "registry":
            extract_registry_conditions(line, conditions)
        elif classification == "network":
            extract_network_conditions(line, conditions)
        elif classification == "system":
            extract_system_conditions(line, conditions)
        elif classification == "application":
            extract_application_conditions(line, conditions)
        elif classification == "service":
            extract_service_conditions(line, conditions)
        elif classification == "file":
            extract_file_conditions(line, conditions)
        else:
            debug(f"[Advertencia] No se pudo clasificar la línea: {line}")
    return conditions
    lines = pseudocode.split("\n")
    for line in lines:
        line = line.strip()
        debug(f"Processing line: {line}")

        extract_process_conditions(line, conditions)
        extract_registry_conditions(line, conditions)
        extract_network_conditions(line, conditions)
        extract_system_conditions(line, conditions)
        extract_application_conditions(line, conditions)
        extract_service_conditions(line, conditions)
        extract_file_conditions(line, conditions)

    logging.debug(f"Extracted conditions: {conditions}")
    return conditions


# def extract_conditions(pseudocode):
#     conditions = {
#         "process": [],
#         "registry": [],
#         "network": [],
#         "system": [],
#         "application": [],
#         "service": [],
#         "file": [],
#     }

#     lines = pseudocode.split("\n")
#     for line in lines:
#         line = line.strip()
#         debug(f"Processing line: {line}")

#         # Process conditions
#         if (
#             "command_line" in line
#             or "command_line CONTAINS" in line
#             or "exe =" in line
#             or "exe=" in line
#             or "parent_exe" in line
#             or "image_path" in line
#             or "process_path" in line
#             or "key" in line
#             or "parent_image_path" in line
#         ):

#             command_line = None
#             key_condition = None
#             exe_condition = None
#             parent_exe_condition = None
#             image_path_condition = None
#             process_path_condition = None
#             parent_image_path_condition = None
#             if "command_line CONTAINS" in line:
#                 command_line = (
#                     line.split("command_line CONTAINS")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                     .replace("\\", "")
#                 )
#             if "command_line ==" in line:
#                 command_line = (
#                     line.split("command_line ==")[1]
#                     .split()[0]
#                     .strip('()"*')
#                     .replace("*", "")
#                     .replace("\\", "")
#                     .replace('"', '\\"')
#                 )
#             if "key =" in line:
#                 key_condition = (
#                     line.split("key =")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                     .replace("\\", "")
#                 )
#             if "exe =" in line:
#                 exe_condition = (
#                     line.split("exe =")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "exe=" in line:
#                 exe_condition = (
#                     line.split("exe=")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "parent_exe =" in line:
#                 parent_exe_condition = (
#                     line.split("parent_exe =")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "image_path ==" in line:
#                 image_path_condition = (
#                     line.split("image_path ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                     .replace("\\", "")
#                 )
#             if "process_path ==" in line:
#                 process_path_condition = (
#                     line.split("process_path ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "parent_image_path ==" in line:
#                 parent_image_path_condition = (
#                     line.split("parent_image_path ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )

#             if command_line:
#                 conditions["process"].append(f'cmd == "{command_line}"')
#             if key_condition:
#                 conditions["process"].append(f'key == "{key_condition}"')
#             if exe_condition:
#                 conditions["process"].append(f'exe == "{exe_condition}"')
#             if parent_exe_condition:
#                 conditions["process"].append(f'parent_exe == "{parent_exe_condition}"')
#             if image_path_condition:
#                 conditions["process"].append(f'image_path == "{image_path_condition}"')
#             if process_path_condition:
#                 conditions["process"].append(
#                     f'process_path == "{process_path_condition}"'
#                 )
#             if parent_image_path_condition:
#                 conditions["process"].append(
#                     f'parent_image_path == "{parent_image_path_condition}"'
#                 )

#         # File conditions
#         if "extension =" in line or "file_path =" in line or "image_path !=" in line:
#             extension_condition = None
#             file_path_condition = None
#             image_path_condition = None
#             if "image_path !=" in line:
#                 image_path_condition = (
#                     line.split("image_path !=")[1]
#                     .strip()
#                     .strip('()"*')
#                     .replace("*", "")
#                     .replace('"', '"')
#                     .replace('"', "")
#                 )
#             if "extension =" in line:
#                 extension_condition = (
#                     line.split("extension =")[1]
#                     .strip()
#                     .strip('()"*')
#                     .replace("*", "")
#                     .replace('"', '"')
#                     .replace('"', "")
#                 )
#             if "file_path =" in line:
#                 file_path_condition = (
#                     line.split("file_path =")[1]
#                     .strip()
#                     .strip("()*")
#                     .replace("*", "")
#                     .replace('"', '"')
#                     .replace('"', "")
#                 )
#             if file_path_condition:
#                 conditions["file"].append(f'"{file_path_condition}" in file_path')
#             if extension_condition:
#                 conditions["file"].append(f'"{extension_condition}" in extension')
#             if image_path_condition:
#                 conditions["file"].append(f'"{image_path_condition}" in image_path')
#             if image_path_condition and file_path_condition:
#                 debug(
#                     f"Extracted file condition: {image_path_condition}, {file_path_condition}"
#                 )
#                 conditions["file"].append(
#                     f'"{image_path_condition}" in image_path and "{file_path_condition}" in file_path'
#                 )
#             if extension_condition and file_path_condition:
#                 debug(
#                     f"Extracted file condition: {extension_condition}, {file_path_condition}"
#                 )
#                 conditions["file"].append(
#                     f'"{extension_condition}" in extension and "{file_path_condition}" in file_path'
#                 )
#             # Menajar casos donde solo exista una condicion
#             elif extension_condition:
#                 conditions["file"].append(f'"{extension_condition}" in extension')
#             elif file_path_condition:
#                 conditions["file"].append(f'"{file_path_condition}" in file_path')

#         # Service conditions
#         if "image_path =" in line:
#             image_path_condition = (
#                 line.split("image_path =")[1]
#                 .strip()
#                 .strip("()*")
#                 .replace("*", "")
#                 .replace('"', '\\"')
#             )
#             debug(f"Extracted service condition: {image_path_condition}")
#             conditions["service"].append(f'"{image_path_condition}" in image_path')

#         if "image_path does not contain" in line:
#             excludes = (
#                 line.split("image_path does not contain")[1]
#                 .strip()
#                 .strip("[]")
#                 .replace('"', "")
#                 .split(",")
#             )
#             exclude_conditions = [
#                 f'"{exclude.strip()}" not in image_path' for exclude in excludes
#             ]
#             final_exclude_condition = " and ".join(exclude_conditions)
#             debug(f"Extracted service exclusion condition: {final_exclude_condition}")
#             conditions["service"].append(final_exclude_condition)

#         # Task conditions

#         # Registry conditions
#         if "Key=" in line or "value=" in line or "key =" in line:
#             key_condition = None
#             value_condition = None
#             if "Key=" in line:
#                 key_condition = line.split("Key=")[1].split()[0].strip(' "*')
#             if "value=" in line:
#                 value_condition = line.split("value=")[1].split()[0].strip(' "*')
#             if "key =" in line:
#                 key_condition = (
#                     line.split("key =")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                     .replace("\\", "")
#                 )
#             if key_condition:
#                 conditions["registry"].append(f'"{key_condition}" in key')
#             if key_condition and value_condition:
#                 debug(
#                     f"Extracted registry condition: {key_condition}, {value_condition}"
#                 )
#                 conditions["registry"].append(
#                     f'"{key_condition}" in key and "{value_condition}" in value'
#                 )
#             elif value_condition:
#                 debug(f"Extracted registry condition: {value_condition}")
#                 conditions["registry"].append(f'"{value_condition}" in value')

#         # Network conditions
#         if (
#             "source_ip CONTAINS" in line
#             or "dest_port ==" in line
#             or "protocol ==" in line
#             or "proto_info" in line
#             or "dest_port >=" in line
#             or "src_port >=" in line
#             or "port ==" in line
#         ):
#             src_ip_condition = None
#             dest_port_condition = None
#             protocol_condition = None
#             src_port_condition = None
#             proto_info_condition = None
#             port_condition = None

#             if "source_ip CONTAINS" in line:
#                 src_ip_condition = (
#                     line.split("source_ip CONTAINS")[1].split()[0].strip(' "*')
#                 )
#             if "dest_port ==" in line:
#                 dest_port_condition = (
#                     line.split("dest_port ==")[1].split()[0].strip(' "*')
#                 )
#             if "protocol ==" in line:
#                 protocol_condition = (
#                     line.split("protocol ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "proto_info" in line:
#                 proto_info_condition = (
#                     line.split("proto_info")[1]
#                     .strip()
#                     .strip("()*")
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "dest_port >=" in line:
#                 dest_port_condition = (
#                     line.split("dest_port >=")[1].split()[0].strip(' "*')
#                 )
#             if "src_port >=" in line:
#                 src_port_condition = (
#                     line.split("src_port >=")[1].split()[0].strip(' "*')
#                 )
#             if "port ==" in line:
#                 port_condition = (
#                     line.split("port ==")[1]
#                     .split()[0]
#                     .strip(' "*')
#                     .strip('()"')
#                     .replace("\\", "")
#                     .replace('"', '\\"')
#                 )
#             if port_condition:
#                 conditions["network"].append(f'"{port_condition}" in port')
#             if src_port_condition:
#                 conditions["network"].append(f'"{src_port_condition}" in src_port')
#             if src_ip_condition:
#                 conditions["network"].append(f'"{src_ip_condition}" in src_ip')
#             if dest_port_condition:
#                 conditions["network"].append(f'"{dest_port_condition}" in dest_port')
#             if protocol_condition:
#                 conditions["network"].append(f'"{protocol_condition}" in protocol')
#             if proto_info_condition:
#                 conditions["network"].append(f'"{proto_info_condition}" in proto_info')
#         # System conditions
#         if (
#             "event_id CONTAINS" in line
#             or "event_message CONTAINS" in line
#             or "param1" in line
#             or "param2" in line
#             or "Thread:remote_create" in line
#             or "raw_event" in line
#             or "log_name ==" in line
#             or "event_code ==" in line
#             or "object_type ==" in line
#             or "subject_security_id !=" in line
#             or "[EventCode]" in line
#             or "[AuthenticationPackageName]" in line
#             or "[Severity]" in line
#             or "[LogonType]" in line
#         ):
#             event_id_condition = None
#             event_message_condition = None
#             raw_event_condition = None
#             log_name_condition = None
#             event_code_condition = None
#             object_type_condition = None
#             subject_security_id_condition = None
#             auth_package_condition = None
#             severity_condition = None
#             logon_type_condition = None
#             param1_condition = None
#             param2_condition = None

#             if "param1 in" in line:
#                 param1_condition = (
#                     line.split("param1 in")[1]
#                     .strip()
#                     .strip(" []*")
#                     .replace('"', "")
#                     .split(",")
#                 )
#             if "param2 ==" in line:
#                 param2_condition = (
#                     line.split("param2 ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "log_name ==" in line:
#                 log_name_condition = (
#                     line.split("log_name ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "event_code ==" in line:
#                 event_code_condition = (
#                     line.split("event_code ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "[EventCode] " in line:
#                 event_code_condition = (
#                     line.split("==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "object_type ==" in line:
#                 object_type_condition = (
#                     line.split("object_type ==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "subject_security_id !=" in line:
#                 subject_security_id_condition = (
#                     line.split("subject_security_id !=")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "event_id CONTAINS" in line:
#                 event_id_condition = (
#                     line.split("event_id CONTAINS")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "event_message CONTAINS" in line:
#                 event_message_condition = (
#                     line.split("event_message CONTAINS")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "Thread:remote_create" in line:
#                 raw_event_condition = (
#                     line.split("Thread:remote_create")[1]
#                     .strip()
#                     .strip("()*")
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "[AuthenticationPackageName]" in line:
#                 auth_package_condition = (
#                     line.split("==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "[Severity]" in line:
#                 severity_condition = (
#                     line.split("==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "[LogonType]" in line:
#                 logon_type_condition = (
#                     line.split("==")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if "raw_event" in line:
#                 raw_event_condition = (
#                     line.split("raw_event CONTAINS")[1]
#                     .split()[0]
#                     .strip('() "*')
#                     .replace("*", "")
#                     .replace('"', '\\"')
#                 )
#             if param1_condition:
#                 conditions["system"].append(f'"{param1_condition}" in param1')
#             if param2_condition:
#                 conditions["system"].append(f'"{param2_condition}" in param2')
#             if event_id_condition:
#                 conditions["system"].append(f'"{event_id_condition}" in event_id')
#             if event_message_condition:
#                 conditions["system"].append(
#                     f'"{event_message_condition}" in event_message'
#                 )
#             if raw_event_condition:
#                 conditions["system"].append(f'"{raw_event_condition}" in raw_event')
#             if log_name_condition:
#                 conditions["system"].append(f'"{log_name_condition}" in log_name')
#             if event_code_condition:
#                 conditions["system"].append(f'"{event_code_condition}" in event_code')
#             if object_type_condition:
#                 conditions["system"].append(f'"{object_type_condition}" in object_type')
#             if subject_security_id_condition:
#                 conditions["system"].append(
#                     f'"{subject_security_id_condition}" in subject_security_id'
#                 )
#             if auth_package_condition:
#                 conditions["system"].append(
#                     f'"{auth_package_condition}" in auth_package'
#                 )
#             if severity_condition:
#                 conditions["system"].append(f'"{severity_condition}" in severity')
#             if logon_type_condition:
#                 conditions["system"].append(f'"{logon_type_condition}" in logon_type')

#         # Application conditions
#         if "app_name CONTAINS" in line or "log_level CONTAINS" in line:
#             app_name_condition = None
#             log_level_condition = None
#             if "app_name CONTAINS" in line:
#                 app_name_condition = (
#                     line.split("app_name CONTAINS")[1].split()[0].strip(' "*')
#                 )
#             if "log_level CONTAINS" in line:
#                 log_level_condition = (
#                     line.split("log_level CONTAINS")[1].split()[0].strip(' "*')
#                 )
#             if app_name_condition:
#                 conditions["application"].append(f'"{app_name_condition}" in app_name')
#             if log_level_condition:
#                 conditions["application"].append(
#                     f'"{log_level_condition}" in log_level'
#                 )

#     debug(f"Extracted conditions: {conditions}")
#     return conditions


def read_pseudocode(file_path):
    try:
        with codecs.open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with codecs.open(file_path, "r", encoding="latin-1") as f:
            return f.read()


def main():
    for analytic_file in os.listdir(analytics_dir):
        if analytic_file.endswith(".txt"):
            analytic_id = analytic_file.split(".")[0]
            pseudocode = read_pseudocode(os.path.join(analytics_dir, analytic_file))
            generate_script(analytic_id, pseudocode)
    print("Scripts generados con éxito.")


if __name__ == "__main__":
    main()
