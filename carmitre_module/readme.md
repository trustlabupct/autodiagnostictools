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

1. **Ejecutar main**:
   ```sh
   Para que el programa funcione vamos a ejecutar solo main, esto ejectura los siguientes
   scripts:
   python scripts/sysmon_config_run.py
   python scripts/sysmon_logs.py
   python scripts/download_analytics.py
   python scripts/generate_scripts.py
   python scripts/run_analyses.py
   python scripts/generate_report.py
   ```

2. **Explicacion de los scripts desarrollados**:

   ````
   sysmon_config_run: El script pide permisos de administrador para poder descargar Sysmon y la configruacion desde una URL, instalarlo y configurarlo como deseamos en este caso
   sysmon_logs: Nos permite obtener la informacion de Sysmon en un formato XML y darle formato JSON que deseamos 
   download_analytics: Accedemos a la pagina de CAR.MITRE y obtenemos las analiticas de CAR.MITRE las cuales podemos descargar en formato TXT
   generate_scripts: Apartir de las analiticas descargar de CAR.MITRE podemos generar scripts personalizados para cada uno de ellos
   run_analyses: Con los scripts generados podemos hacer comprobaciones con logs logs que obtenemos de Sysmon, para comprobar si existe coincidencia entre los logs y el script generado
   generate_report: Si existe coincidencia es decit match, se generara un CSV con la informacion y un JSON con la informacion mas especifica detallando que error y de que año es
   ```