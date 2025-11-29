from dotenv import load_dotenv
import os
import requests
import urllib3

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