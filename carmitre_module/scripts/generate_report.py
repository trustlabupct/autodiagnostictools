import os
import json
import csv
import re

# Directorio de salida donde se encuentran los archivos JSON
output_dir = os.path.join(
    os.path.expanduser("~"),
    "Documents",
    "GitHub",
    "autodiagnostictools",
    "reports_module",
)

# Ruta del archivo CSV que se generará
report_file = os.path.join(output_dir, "report.csv")

# Verificar si el directorio de salida existe
if not os.path.exists(output_dir):
    print(f"El directorio {output_dir} no existe.")
    exit(1)

# Patrón para extraer el analytic_id del nombre del archivo
pattern = r"suspicious_results_(.+)\.json"


def verify_output_dir(output_dir):
    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"El directorio {output_dir} no existe.")


def read_json_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error al leer el archivo {file_path}: {e}")
        return None


# Funcion para generar el informe CSV
def generate_report():
    verify_output_dir(output_dir)

    # Abrir el archivo CSV para escritura
    with open(report_file, "w", encoding="utf-8", newline="") as report:
        writer = csv.writer(report)
        # Escribir la cabecera del CSV
        writer.writerow(["analytic_id", "type", "details"])
        # Iterar sobre los archivos en el directorio de salida
        for file_name in os.listdir(output_dir):
            if file_name.startswith("suspicious_results_") and file_name.endswith(
                ".json"
            ):
                # Extraer el analytic_id usando una expresión regular
                match = re.match(pattern, file_name)
                if match:
                    analytic_id = match.group(1)
                    file_path = os.path.join(output_dir, file_name)

                    try:
                        # Leer el archivo JSON
                        with open(file_path, "r", encoding="utf-8") as file:
                            data = json.load(file)
                    except (IOError, json.JSONDecodeError) as e:
                        print(f"Error al leer el archivo {file_name}: {e}")
                        continue

                    # Lista de tipos de logs sospechosos
                    suspicious_types = [
                        "suspicious_processes",
                        "suspicious_registry_keys",
                        "suspicious_network_logs",
                        "suspicious_system_logs",
                        "suspicious_application_logs",
                        "suspicious_service_logs",
                        "suspicious_file_logs",
                    ]

                    # Iterar sobre cada tipo de log sospechoso
                    for log_type in suspicious_types:
                        # Obtener la lista de items para el tipo actual
                        items = data.get(log_type, [])
                        for item in items:
                            # Escribir una fila en el CSV por cada item
                            writer.writerow(
                                [
                                    analytic_id,
                                    log_type.replace("suspicious_", ""),
                                    json.dumps(item),
                                ]
                            )
                else:
                    print(f"No se pudo extraer analytic_id del archivo {file_name}")
    print(f"Reporte generado en: {report_file}")


def main():
    try:
        generate_report()
    except FileNotFoundError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
