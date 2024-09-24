import requests
from bs4 import BeautifulSoup
import os


# URL de la página de CAR MITRE Analytics
car_analytics_url = "https://car.mitre.org/analytics/"


# Función para descargar analíticas de CAR MITRE
def download_analytics():
    # Directorio donde se guardarán las analíticas
    analytics_dir = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "GitHub",
        "autodiagnostictools",
        "carmitre_module",
        "analytics",
    )

    # Crear el directorio si no existe
    if not os.path.exists(analytics_dir):
        os.makedirs(analytics_dir)

    response = requests.get(car_analytics_url)
    print(f"Accediendo a {car_analytics_url}: Estado {response.status_code}")

    if response.status_code != 200:
        raise Exception(
            f"Error al acceder a {car_analytics_url}: {response.status_code}"
        )

    soup = BeautifulSoup(response.content, "html.parser")
    analytics_links = soup.find_all("a", href=True)

    print(f"Encontrados {len(analytics_links)} enlaces en la página principal.")

    for link in analytics_links:
        if link["href"].startswith("/analytics/"):
            analytic_url = "https://car.mitre.org" + link["href"]
            print(f"Accediendo a {analytic_url}")
            analytic_response = requests.get(analytic_url)
            print(
                f"Accediendo a {analytic_url}: Estado {analytic_response.status_code}"
            )

            if analytic_response.status_code != 200:
                raise Exception(
                    f"Error al acceder a {analytic_url}: {analytic_response.status_code}"
                )

            analytic_soup = BeautifulSoup(analytic_response.content, "html.parser")

            # Buscar la sección de pseudocódigo
            pseudocode = None

            # Primero buscar el pseudocódigo usando encabezados
            headers = analytic_soup.find_all(["h1", "h2", "h3", "h4"])
            for header in headers:
                if "Pseudocode" in header.get_text():
                    pseudocode = header.find_next("pre")
                    break

            # Si no se encuentra el pseudocódigo usando encabezados, buscar en todas las etiquetas <pre>
            if not pseudocode:
                pre_tags = analytic_soup.find_all("pre")
                for pre in pre_tags:
                    if "search Process:Create" in pre.text:
                        pseudocode = pre
                        break

            if pseudocode:
                # Extraer la ID de la analítica desde la URL
                analytic_id = link["href"].split("/")[-2]
                file_name = f"{analytic_id}.txt"
                file_path = os.path.join(analytics_dir, file_name)

                # Guardar el pseudocódigo en un archivo
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(pseudocode.text)
                print(f"Descargado pseudocódigo: {file_name}")
            else:
                print(f"No se encontró pseudocódigo en {analytic_url}")


def main():
    try:
        download_analytics()
    except Exception as e:
        print(f"Error durante la descarga de analíticas: {e}")
        return False

    return True


if __name__ == "__main__":
    main()
