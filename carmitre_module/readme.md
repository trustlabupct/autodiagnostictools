# CAR MITRE Risk Analysis

Este proyecto utiliza los pseudocódigos de las analíticas de CAR MITRE para realizar pruebas de seguridad automatizadas en pequeñas empresas. El objetivo es identificar actividades sospechosas en los logs de procesos y registros.

## Estructura del Proyecto

- `analytics/`: Almacena las analíticas descargadas de CAR MITRE.
- `logs/`: Contiene los logs de procesos y registros que se analizarán.
- `output/`: Guarda los resultados generados por el análisis.
- `scripts/`: Contiene los scripts para ejecutar los análisis y generar reportes.
- `config/`: Contiene el archivo de configuración.
- `README.md`: Este archivo.

## Cómo Usar

1. **Ejecutar run_All**:
   ```sh
   Para que el programa funcione vamos a ejecutar solo run_all.py, esto ejectura los siguientes
   scripts:
   python scripts/download_analytics.py
   python scripts/generate_scripts.py
   python scripts/run_analyses.py
   python scripts/generate_report.py
   ```