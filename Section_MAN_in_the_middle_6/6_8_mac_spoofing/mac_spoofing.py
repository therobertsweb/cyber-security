import subprocess
import re
import random

class MACSpoofing:
    """Clase para realizar operaciones de spoofing de direcciones MAC en una interfaz de red específica.

    Args:
        interface (str): La interfaz de red en la que se realizarán las operaciones de spoofing.
    """
    def __init__(self, interface):
        self.interface = interface
        self.mac_file = f"{self.interface}_mac.txt"

    def read_mac_from_file(self):
        """Lee la dirección MAC almacenada en un archivo.

        Returns:
            str: La dirección MAC leída del archivo. Devuelve None si el archivo no existe.
        """
        try:
            with open(self.mac_file, 'r') as file:
                return file.read().strip()
        except FileNotFoundError:
            return None

    def write_mac_to_file(self, mac):
        """Escribe una dirección MAC en un archivo.

        Args:
            mac (str): La dirección MAC a almacenar.
        """
        with open(self.mac_file, 'w') as file:
            file.write(mac)

    def get_current_mac(self):
        """Obtiene la dirección MAC actual de la interfaz de red.

        Returns:
            str: La dirección MAC actual.

        Raises:
            ValueError: Si no se puede obtener la dirección MAC o si el comando ifconfig falla.
        """
        try:
            result = subprocess.check_output(["ifconfig", self.interface])
            mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(result))
            if mac_address:
                return mac_address.group(0)
            else:
                raise ValueError("No se pudo obtener la dirección MAC.")
        except subprocess.CalledProcessError:
            raise ValueError("No se pudo ejecutar ifconfig.")

    def change_mac(self, new_mac):
        """Cambia la dirección MAC de la interfaz de red.

        Args:
            new_mac (str): La nueva dirección MAC a establecer.
        """
        subprocess.call(["sudo", "ifconfig", self.interface, "down"])
        subprocess.call(["sudo", "ifconfig", self.interface, "hw", "ether", new_mac])
        subprocess.call(["sudo", "ifconfig", self.interface, "up"])

    def validate_mac(self, mac):
        """Valida el formato de una dirección MAC.

        Args:
            mac (str): La dirección MAC a validar.

        Returns:
            bool: True si la dirección MAC es válida, False en caso contrario.
        """
        return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

    def generate_random_mac(self):
        """Genera una dirección MAC aleatoria válida.

        Returns:
            str: Una dirección MAC aleatoria.
        """
        return "02:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 127),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
