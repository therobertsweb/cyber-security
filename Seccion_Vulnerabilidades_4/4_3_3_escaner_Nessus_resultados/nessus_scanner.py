from dotenv import load_dotenv
import os
import requests
import urllib3
import time

# Suprimir advertencias relacionadas con certificados no verificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusScanner:
    """Representa un escáner que interactúa con la API de Nessus para realizar y gestionar escaneos de vulnerabilidades."""

    def __init__(self):
        """Inicializa el escáner cargando las credenciales de Nessus desde variables de entorno."""
        load_dotenv()
        self.base_url = os.getenv("NESSUS_URL")
        self.username = os.getenv("NESSUS_USERNAME")
        self.password = os.getenv("NESSUS_PASSWORD")
        self.token = None

    def create_session(self):
        """Crea una sesión en Nessus y almacena el token de sesión.

        Returns:
            bool: True si la sesión se crea exitosamente, False de lo contrario.
        """
        response = requests.post(f"{self.base_url}/session", json={"username": self.username, "password": self.password}, verify=False)
        if response.status_code == 200:
            self.token = response.json()['token']
        else:
            print(f"Error al crear la sesión: {response.status_code} - {response.text}")
            return False
        return True

    def get_policies(self):
        """Obtiene y muestra la lista de políticas de escaneo definidas en Nessus."""
        if not self.token:
            print("No hay token de sesión. Iniciando sesión...")
            if not self.create_session():
                return
        
        headers = {"X-Cookie": f"token={self.token};"}
        response = requests.get(f"{self.base_url}/policies", headers=headers, verify=False)
        if response.status_code == 200:
            policies = response.json()
            print("Lista de políticas", policies)
        else:
            print(f"Error al obtener las políticas: {response.status_code} - {response.text}")

    def create_scan(self, uuid, scan_name, text_targets, policy_id=None, description="", enabled=True, launch="ON_DEMAND"):
        """Crea un nuevo escaneo en Nessus.

        Args:
            uuid (str): UUID del escáner.
            scan_name (str): Nombre del escaneo.
            text_targets (str): Direcciones IP o nombres de host a escanear.
            policy_id (str, optional): ID de la política a utilizar. Defaults to None.
            description (str, optional): Descripción del escaneo. Defaults to "".
            enabled (bool, optional): Indica si el escaneo está habilitado. Defaults to True.
            launch (str, optional): Modo de lanzamiento del escaneo. Defaults to "ON_DEMAND".
        """
        if not self.token:
            print("No hay token de sesión. Iniciando sesión...")
            if not self.create_session():
                return
        
        scan_settings = {
            "uuid": uuid,
            "settings": {
                "name": scan_name,
                "description": description,
                "enabled": str(enabled).lower(),
                "launch": launch,
                "text_targets": text_targets,
                "agent_group_id": [],
                "policy_id": policy_id
            }
        }

        headers = {"X-Cookie": f"token={self.token};"}
        response = requests.post(f"{self.base_url}/scans", json=scan_settings, headers=headers, verify=False)

        if response.status_code == 200:
            scan = response.json()
        else:
            print(f"Error al crear el escaneo en Nessus: {response.status_code} - {response.text}")

    def list_scans(self, folder_id=None, last_modification_date=None):
        """Lista todos los escaneos disponibles en Nessus.

        Args:
            folder_id (int, optional): ID del directorio para filtrar escaneos. Defaults to None.
            last_modification_date (str, optional): Filtra escaneos por la última fecha de modificación. Defaults to None.

        Returns:
            list: Lista de escaneos si la operación es exitosa, None de lo contrario.
        """
        if not self.token:
            print("No hay token de sesión. Iniciando sesión...")
            if not self.create_session():
                return
            
        headers = {"X-Cookie": f"token={self.token};"}
        params = {}
        if folder_id:
            params["folder_id"] = folder_id
        if last_modification_date:
            params["last_modification_date"] = last_modification_date

        response = requests.get(f"{self.base_url}/scans", headers=headers, params=params, verify=False)

        if response.status_code == 200:
            scans = response.json().get('scans', [])
            if scans:
                for scan in scans:
                    print(f"ID: {scan['id']}, Nombre: {scan['name']}, Estado: {scan['status']}")
            else:
                print("No se encontraron escaneos en Nessus.")
            return scans
        else:
            print(f"Error al obtener el listado de escaneos: {response.status_code} - {response.text}")
            return None

    def export_scan(self, scan_id, format_type, file_id=None):
        """Exporta y descarga los resultados de un escaneo específico de Nessus.

        Args:
            scan_id (int): ID del escaneo a exportar.
            format_type (str): Formato de archivo de la exportación (ej. 'pdf', 'csv').
            file_id (int, optional): ID del archivo si ya se inició una exportación. Defaults to None.
        """
        if not self.token:
            print("No hay token de sesión. Iniciando sesión...")
            if not self.create_session():
                return
            
        headers = {"X-Cookie": f"token={self.token};"}
        export_payload = {'format': format_type, 'template_id': 21}
        export_response = requests.post(f"{self.base_url}/scans/{scan_id}/export", json=export_payload, headers=headers, verify=False)

        if export_response.status_code != 200:
            print(f"Error al exportar el escaneo: {export_response.status_code} - {export_response.text}")
            return None

        if not file_id:
            file_id = export_response.json()['file']

        polling_interval = 10  # Intervalo de sondeo para verificar el estado del reporte
        while True:
            status_response = requests.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/status", headers=headers, verify=False)
            print(f"Consultando el estado del informe. Estado: {status_response.json()['status']}")
            if status_response.status_code == 200 and status_response.json()['status'] == 'ready':
                break
            time.sleep(polling_interval)

        download_response = requests.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/download", headers=headers, verify=False)

        if download_response.status_code == 200:
            file_path = f"scan_{scan_id}_export.{format_type}"
            with open(file_path, 'wb') as f:
                f.write(download_response.content)
            print(f"Escaneo exportado y descargado con éxito en {file_path}")
        else:
            print(f"Error al descargar el escaneo exportado: {download_response.status_code} - {download_response.text}")