import os
import sys
import logging
import argparse

# Configurar el logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Paths of the modules to be imported
sys.path.append(os.path.join(os.path.dirname(__file__), 'carmitre_module'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'clamav_module'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'nmap_module'))

# Import modules
try:
    from carmitre_module import main as carmitre_main
    from clamav_module import main as clamav_main
    from nmap_module import main as nmap_main
except ImportError as e:
    logging.error(f"Error importing modules: {e}")
    sys.exit(1)

def run_analysis(module_name, module_main):
    """
    Ejecuta el análisis de un módulo específico y captura errores.
    """
    try:
        logging.info(f"Running {module_name}...\n")
        module_main.main()
        logging.info(f"{module_name} finished.\n")
    except Exception as e:
        logging.error(f"Error running {module_name}: {e}")

def main():
    # Run analysis for each module
    logging.info("Starting security analysis...\n")

    run_analysis("carmitre_module", carmitre_main)
    run_analysis("clamav_module", clamav_main)
    run_analysis("nmap_module", nmap_main)

    logging.info("Security analysis finished. Reports are available in the folder.\n")

if __name__ == "__main__":
    # Si deseas usar argparse, puedes agregar opciones aquí
    parser = argparse.ArgumentParser(description="Run security analysis using different modules.")
    args = parser.parse_args()
    
    main()
