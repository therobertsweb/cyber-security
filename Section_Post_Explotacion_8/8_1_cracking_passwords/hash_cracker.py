import hashlib
import logging
import bcrypt
from passlib.hash import scrypt, argon2
import argparse
from tqdm import tqdm

# Configuración básica del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class HashCracker:
    """Clase para descifrar hashes utilizando una lista de contraseñas."""
    
    def __init__(self):
        """Inicializa la clase HashCracker con los hashes soportados."""
        self.supported_hashes = {
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
            'sha512': hashlib.sha512,
            'bcrypt': bcrypt.hashpw,
            'scrypt': scrypt.encrypt,
            'argon2': argon2.using()
        }

    def crack_hash(self, hash_value, wordlist_path, hash_type):
        """Intenta descifrar un hash utilizando una lista de contraseñas.
        
        Args:
            hash_value (str): El hash a descifrar.
            wordlist_path (str): La ruta del archivo con la lista de contraseñas.
            hash_type (str): El tipo de hash que se debe utilizar.
        
        Returns:
            str: La contraseña que corresponde al hash si se encuentra, de lo contrario None.
        
        Raises:
            ValueError: Si el tipo de hash no es soportado.
        """
        if hash_type not in self.supported_hashes:
            raise ValueError(f'Tipo de hash inválido: {hash_type}. Los tipos soportados son: {list(self.supported_hashes)}')

        total_lines = sum(1 for _ in open(wordlist_path, 'r', encoding='latin-1'))
        logging.info(f"Intentando descifrar el hash '{hash_value}' usando '{hash_type}' con una lista de {total_lines} contraseñas.")       

        with open(wordlist_path, 'r', encoding='latin-1') as file:
            for line in tqdm(file, desc="Descifrando", total=total_lines):
                password = line.strip()
                if hash_type == 'bcrypt' and bcrypt.checkpw(password.encode(), hash_value.encode()):
                    return password
                elif hash_type == 'scrypt' and scrypt.verify(password, hash_value):
                    return password
                elif hash_type == 'argon2' and argon2.verify(password, hash_value):
                    return password
                else:
                    hash_function = self.supported_hashes[hash_type]
                    if hash_function(password.encode()).hexdigest() == hash_value:
                        return password
        return None

def main():
    """Función principal para el script de descifrado de hashes."""
    parser = argparse.ArgumentParser(description="Descifra un hash de una contraseña.")
    parser.add_argument('hash', help='El hash a descifrar')
    parser.add_argument('wordlist', help='La ruta a la lista de contraseñas')
    parser.add_argument('--hash-type', help='El tipo de hash que se debe utilizar', default='md5')
    args = parser.parse_args()

    cracker = HashCracker()
    result = cracker.crack_hash(args.hash, args.wordlist, args.hash_type)
    if result:
        logging.info(f"[+] Contraseña encontrada: {result}")
    else:
        logging.info("[-] No se encontraron coincidencias.")

if __name__ == "__main__":
    main()