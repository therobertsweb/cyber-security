import requests
import tempfile
import webbrowser
import time
import os

class AuthSession:
    """
    Clase para manejar una sesión autenticada con un servidor web.

    Attributes:
        base_url (str): La URL base del servidor.
        username (str): Nombre de usuario para la autenticación.
        password (str): Contraseña para la autenticación.
        session (requests.Session): Objeto de sesión de requests.
        headers (dict): Cabeceras HTTP para las solicitudes.
    """

    def __init__(self, base_url, username, password):
        """
        Inicializa una nueva instancia de AuthSession.

        Args:
            base_url (str): La URL base del servidor.
            username (str): Nombre de usuario para la autenticación.
            password (str): Contraseña para la autenticación.
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.base_url}/login.php',
            'Origin': self.base_url,
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }

    def login(self):
        """
        Realiza la autenticación en el servidor.

        Returns:
            requests.Response: Respuesta del servidor tras intentar autenticarse.
        """
        login_data = {
            'login': self.username,
            'password': self.password,
            'security_level': '0',
            'form': 'submit'
        }

        response = self.session.post(f'{self.base_url}/login.php', headers=self.headers, data=login_data)
        return response

    def authenticate_and_fetch(self, target_url):
        """
        Autentica al usuario y accede a una URL objetivo.

        Args:
            target_url (str): URL a la que se quiere acceder tras la autenticación.

        Returns:
            requests.Response: Respuesta del servidor tras acceder a la URL objetivo.
        """
        response_login = self.login()

        if f"Welcome {self.username}".lower() in response_login.text.lower():
            print("Autenticación exitosa.")
            response = self.session.get(target_url, headers=self.headers)
            print("Acceso autenticado a la URL realizado satisfactoriamente.")
            return response
        else:
            print("Error en la autenticación.")
            print("Código de estado de la respuesta de login:", response_login.status_code)
            return response_login

if __name__ == "__main__":
    # Parámetros de configuración
    base_url = "http://192.168.138.129:8080"
    username = "usuario1"
    password = "1234"
    auth_session = AuthSession(base_url, username, password)

    # Especificar la URL a la que queremos acceder
    target_url = 'http://192.168.138.129:8080/htmli_get.php'
    response = auth_session.authenticate_and_fetch(target_url)

    # Mostrar la página web obtenida
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as file:
        file.write(response.content.decode('utf-8'))
        temp_html_path = file.name

    webbrowser.open(f"file://{temp_html_path}")

    try:
        print("Pulsa Ctrl+C para cerrar el programa y eliminar el fichero temporal...")
        time.sleep(999999)
    except KeyboardInterrupt:
        os.unlink(temp_html_path)
        print(f"Archivo temporal '{temp_html_path}' eliminado...")