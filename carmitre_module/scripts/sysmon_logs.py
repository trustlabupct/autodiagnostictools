import os
import json
import xmltodict
from win32evtlog import EvtQuery, EvtNext, EvtRender, EvtRenderEventXml, EvtQueryReverseDirection
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
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()


# Definir los Event IDs que nos interesan por cada tipo de evento
EVENT_IDS_PROCESS = [1]  # Event ID 1 para procesos
EVENT_IDS_NETWORK = [3]  # Event ID 3 para red
EVENT_IDS_FILE = [11]    # Event ID 11 para archivos
EVENT_IDS_REGISTRY = [12, 13]  # Event IDs 12, 13 para registro
EVENT_IDS_APPLICATION = [7]  # Event ID 7 para aplicaciones
EVENT_IDS_SYSTEM = [6]  # Event ID 6 para sistema

# Descripciones de los Event IDs
EVENT_ID_DESCRIPTIONS = {
    1: "Process creation",
    3: "Network connection",
    11: "File creation time changed",
    12: "Registry object added",
    13: "Registry value set",
    7: "Image loaded",
    6: "Driver loaded",
}

# Función para capturar eventos y convertir el XML a JSON formateado
def export_events(event_ids, output_file):
    try:
        event_ids_str = " or ".join([f"System/EventID={eid}" for eid in event_ids])
        query = f"*[{event_ids_str}]"

        query_handle = EvtQuery(
            "Microsoft-Windows-Sysmon/Operational",
            EvtQueryReverseDirection,
            query
        )

        events_list = []
        while True:
            events = EvtNext(query_handle, 10)
            if not events:
                break

            for event in events:
                xml_event = EvtRender(event, EvtRenderEventXml)
                event_data = xml_event

                # Convertir XML a diccionario
                event_dict = xmltodict.parse(event_data)

                # Formatear los datos para una salida más clara en JSON
                sys_info = event_dict.get('Event', {}).get('System', {})
                event_id = int(sys_info.get('EventID', 0))
                time_generated = sys_info.get('TimeCreated', {}).get('@SystemTime', '')
                computer_name = sys_info.get('Computer', '')

                event_data = event_dict.get('Event', {}).get('EventData', {}).get('Data', [])

                formatted_event = {
                    'event_id': event_id,
                    'description': EVENT_ID_DESCRIPTIONS.get(event_id, "Unknown"),
                    'time_generated': time_generated,
                    'computer_name': computer_name,
                    'details': {data.get('@Name'): data.get('#text', '') for data in event_data}
                }

                events_list.append(formatted_event)

        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(events_list, f, indent=4)
        print(f"Eventos exportados a {output_file} ({len(events_list)} eventos)")

    except Exception as e:
        print(f"Error al capturar eventos: {e}")

def main():
    run_as_admin()

    try:
        base_dir = os.path.join(
            os.path.expanduser("~"),
            "Documents",
            "GitHub",
            "autodiagnostictools",
            "carmitre_module",
            "logs",
        )

        if not os.path.exists(base_dir):
            os.makedirs(base_dir)

        export_events(
            EVENT_IDS_PROCESS,
            os.path.join(base_dir, "process_logs.json"),
        )

        export_events(
            EVENT_IDS_NETWORK,
            os.path.join(base_dir, "network_logs.json"),
        )

        export_events(
            EVENT_IDS_FILE,
            os.path.join(base_dir, "file_logs.json"),
        )

        export_events(
            EVENT_IDS_REGISTRY,
            os.path.join(base_dir, "registry_logs.json"),
        )

        export_events(
            EVENT_IDS_APPLICATION,
            os.path.join(base_dir, "application_logs.json"),
        )

        export_events(
            EVENT_IDS_SYSTEM,
            os.path.join(base_dir, "system_logs.json"),
        )

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
