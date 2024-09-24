import json


def load_process_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error decodificando JSON en el archivo: {file_path}")
        return []


def load_registry_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error decodificando JSON en el archivo: {file_path}")
        return []


def load_network_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error decodificando JSON en el archivo: {file_path}")
        return []


def load_system_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error decodificando JSON en el archivo: {file_path}")
        return []


def load_application_logs(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {file_path}")
        return []
    except json.JSONDecodeError:
        print(f"Error decodificando JSON en el archivo: {file_path}")
        return []
