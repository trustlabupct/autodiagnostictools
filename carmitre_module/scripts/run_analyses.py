import sys
import os
import importlib.util


def run_analyses():
    base_dir = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "GitHub",
        "autodiagnostictools",
        "carmitre_module",
    )
    scripts_dir = os.path.join(base_dir, "scripts", "generated")

    # Agregar scripts_dir al PYTHONPATH
    if scripts_dir not in sys.path:
        sys.path.append(scripts_dir)
        print(f"Added {scripts_dir} to PYTHONPATH.")

    for script in os.listdir(scripts_dir):
        if script.startswith("analyze_") and script.endswith(".py"):
            module_name = script[:-3]  # Remove the .py extension
            module_path = os.path.join(scripts_dir, script)
            try:
                # Importar el módulo usando importlib.util si hay guiones en el nombre
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Ejecutar la función main del módulo si existe
                if hasattr(module, "main"):
                    print(f"Running analysis: {module_name}")
                    module.main()
                else:
                    print(f"Error: Module {module_name} does not have a main function.")
            except Exception as e:
                print(f"Error: {e}")


def main():
    run_analyses()


if __name__ == "__main__":
    main()
