import pyzipper
import argparse
import logging
from tqdm import tqdm

# Configuración básica del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ZipCracker:
    """Clase para descifrar archivos ZIP utilizando un diccionario de contraseñas.
    """

    def __init__(self, ruta_archivo_zip):
        """Inicializa la clase ZipCracker.

        Args:
            ruta_archivo_zip (str): Ruta del archivo ZIP a descifrar.

        Raises:
            FileNotFoundError: Si el archivo ZIP no existe.
            pyzipper.BadZipFile: Si el archivo ZIP no es válido.
        """
        try:
            self.archivo_zip = pyzipper.AESZipFile(ruta_archivo_zip)
        except FileNotFoundError:
            logging.error(f"El archivo {ruta_archivo_zip} no existe.")
            raise
        except pyzipper.BadZipFile:
            logging.error(f"El archivo {ruta_archivo_zip} no es un archivo zip válido.")
            raise

    def crack_zip(self, wordlist):
        """Intenta descifrar el archivo ZIP utilizando un diccionario de contraseñas.

        Args:
            wordlist (str): Ruta del archivo que contiene las contraseñas a probar.

        Returns:
            str: La contraseña encontrada, o None si no se encuentra ninguna coincidencia.

        Raises:
            FileNotFoundError: Si el archivo de contraseñas no existe.
            Exception: Si ocurre algún error al leer el archivo de contraseñas.
        """
        try:
            with open(wordlist, 'rb') as archivo:
                passwords = archivo.readlines()
        except FileNotFoundError:
            logging.error(f"El archivo '{wordlist}' no existe.")
            raise
        except Exception as e:
            logging.error(f"Se produjo un error al leer el archivo de contraseñas '{wordlist}': {str(e)}")
            raise

        logging.info(f"Intentando descifrar el archivo ZIP con una lista de {len(passwords)} contraseñas.")
        for password in tqdm(passwords, desc="Descifrando ZIP", unit="contraseña"):
            try:
                self.archivo_zip.pwd = password.strip()
                self.archivo_zip.extractall()
            except (RuntimeError, pyzipper.BadZipFile, pyzipper.LargeZipFile) as e:
                logging.debug(f"Fallo con {password.strip().decode()}: {str(e)}")
                continue
            else:
                password = password.decode().strip()
                return password
        return None

def main():
    """Función principal que maneja los argumentos de la línea de comandos y ejecuta el descifrado."""
    parser = argparse.ArgumentParser(description="Descifra un fichero comprimido .ZIP")
    parser.add_argument("zipfile", help='La ruta al archivo .ZIP')
    parser.add_argument("wordlist", help='La ruta al diccionario de contraseñas.')
    args = parser.parse_args()

    cracker = ZipCracker(args.zipfile)

    resultado = cracker.crack_zip(args.wordlist)

    if resultado:
        logging.info(f"[+] Contraseña encontrada: {resultado}")
    else:
        logging.info("[-] No se encontraron coincidencias.")

if __name__ == '__main__':
    main()