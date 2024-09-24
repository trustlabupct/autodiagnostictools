import os
import requests
import zipfile
import subprocess
import sys
import ctypes


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if not is_admin():
        print("Intentando ejecutar como administrador...")
        # Relanzar el script con privilegios de administrador
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()


def download_sysmon():
    # URL de descarga de Sysmon
    sysmon_url = "https://download.sysinternals.com/files/Sysmon.zip"

    # Directorio para guardar Sysmon
    sysmon_dir = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "GitHub",
        "autodiagnostictools",
        "carmitre_module",
    )
    sysmon_zip = os.path.join(sysmon_dir, "Sysmon.zip")

    # Crear el directorio si no existe
    if not os.path.exists(sysmon_dir):
        os.makedirs(sysmon_dir)

    # Descargar Sysmon
    print("Descargando Sysmon...")
    response = requests.get(sysmon_url)
    if response.status_code == 200:
        with open(sysmon_zip, "wb") as file:
            file.write(response.content)
        print("Descarga completada.")
    else:
        raise Exception(f"Error al descargar Sysmon: {response.status_code}")

    # Descomprimir el archivo ZIP
    print("Descomprimiendo Sysmon...")
    with zipfile.ZipFile(sysmon_zip, "r") as zip_ref:
        zip_ref.extractall(sysmon_dir)
    print("Extracción completada.")

    sysmon_exe = os.path.join(
        sysmon_dir, "Sysmon64.exe"
    )  # Corregir el nombre del ejecutable
    return sysmon_exe


def download_sysmon_config():
    # URL del archivo de configuración de Sysmon
    config_url = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

    # Directorio de configuración
    config_dir = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "GitHub",
        "autodiagnostictools",
        "carmitre_module",
    )
    config_file = os.path.join(config_dir, "sysmonconfig-export.xml")

    # Descargar el archivo de configuración
    print("Descargando archivo de configuración de Sysmon...")
    response = requests.get(config_url)
    if response.status_code == 200:
        with open(config_file, "wb") as file:
            file.write(response.content)
        print("Configuración descargada.")
    else:
        raise Exception(
            f"Error al descargar el archivo de configuración: {response.status_code}"
        )

    return config_file


def is_sysmon_installed():

    result = subprocess.run(["sc", "query", "Sysmon64"], capture_output=True, text=True)
    return "RUNNING" in result.stdout


def install_sysmon(sysmon_exe, config_file):
    # Comando para instalar y configurar Sysmon
    print("Instalando y configurando Sysmon...")
    try:
        subprocess.run([sysmon_exe, "-accepteula", "-i", config_file], check=True)
        print("Sysmon instalado y configurado.")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error al instalar Sysmon: {e}")


def main():
    # Asegurarse de que se ejecuta como administrador
    run_as_admin()

    # Descargar e instalar Sysmon
    try:
        sysmon_exe = download_sysmon()
        config_file = download_sysmon_config()
        install_sysmon(sysmon_exe, config_file)
    except Exception as e:
        print(f"Error: {e}")
        return False

    return True


if __name__ == "__main__":
    main()
