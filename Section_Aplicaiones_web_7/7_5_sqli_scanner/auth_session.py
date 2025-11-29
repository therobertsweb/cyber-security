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
        username (str): El nombre de usuario para autenticarse.
        password (str): La contraseña para autenticarse.
        security_level (int): El nivel de seguridad para la autenticación.
        session (requests.Session): La sesión de requests para mantener la autenticación.
        headers (dict): Encabezados HTTP utilizados en las peticiones.
    """

    def __init__(self, base_url, username, password, security_level=0):
        """
        Inicializa una instancia de AuthSession.

        Args:
            base_url (str): La URL base del servidor.
            username (str): El nombre de usuario para autenticarse.
            password (str): La contraseña para autenticarse.
            security_level (int, optional): El nivel de seguridad para la autenticación. Por defecto es 0.
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.security_level = security_level
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
        # Creamos una sesión autenticada
        self.login()

    def login(self):
        """
        Realiza la autenticación con el servidor y establece la sesión.

        Returns:
            requests.Response: La respuesta HTTP de la petición de login.
        """
        login_data = {
            'login': self.username,
            'password': self.password,
            'security_level': self.security_level,
            'form': 'submit'
        }

        response = self.session.post(f'{self.base_url}/login.php', headers=self.headers, data=login_data)
        if f"Welcome {self.username}".lower() in response.text.lower():
            print("Autenticación exitosa.")
        else:
            print("Error en la autenticación.")
            print("Código de estado de la respuesta de login:", response.status_code)
        return response
    
    def get(self, target_url, **kwargs):
        """
        Realiza una petición GET autenticada.

        Args:
            target_url (str): La URL de destino para la petición GET.
            **kwargs: Parámetros adicionales para la petición GET.

        Returns:
            requests.Response: La respuesta HTTP de la petición GET.
        """
        return self.session.get(target_url, headers=self.headers, **kwargs)
    
    def post(self, target_url, data):
        """
        Realiza una petición POST autenticada.

        Args:
            target_url (str): La URL de destino para la petición POST.
            data (dict): Los datos a enviar en la petición POST.

        Returns:
            requests.Response: La respuesta HTTP de la petición POST.
        """
        return self.session.post(target_url, headers=self.headers, data=data)

if __name__ == "__main__":
    # URL base del servidor
    base_url = "http://192.168.138.129:8080"
    # Credenciales de usuario
    username = "usuario1"
    password = "1234"

    # Crear una sesión autenticada
    auth_session = AuthSession(base_url, username, password)

    # Especificar la URL a la que queremos acceder
    target_url = 'http://192.168.138.129:8080/xss_get.php'
    response = auth_session.get(target_url)

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