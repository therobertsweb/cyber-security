import asyncio
import aiohttp
import os
from urllib.parse import urlparse
from colorama import init, Fore
from tqdm.asyncio import tqdm

# Inicialización de colorama para color en la terminal
init(autoreset=True)
GREEN = Fore.GREEN
RESET = Fore.RESET
YELLOW = Fore.YELLOW

class WebContentDiscovery:
    """Clase para la detección de contenido web mediante el escaneo de URLs generadas
    a partir de una palabra lista y una base URL.

    Attributes:
        base_url (str): URL base que será utilizada para generar las URLs de escaneo.
        wordlist (str): Ruta del archivo que contiene las palabras para generar las URLs.
        extensions (list): Lista de extensiones que se anexarán a las palabras de la wordlist.
        timeout (int): Tiempo máximo de espera para una respuesta del servidor.
        follow_redirects (bool): Indica si se deben seguir las redirecciones HTTP.
        verify_ssl (bool): Indica si se debe verificar el certificado SSL.
        output_path (str): Ruta del directorio donde se almacenarán los reportes.
        user_agent (str): Agente de usuario que se enviará en las solicitudes HTTP.
    """
    def __init__(self, base_url, wordlist, extensions=[], timeout=5, follow_redirects=False, verify_ssl=False, output_path='reports'):
        """Inicializa la clase WebContentDiscovery con los parámetros especificados.

        Args:
            base_url (str): URL base para el escaneo.
            wordlist (str): Archivo con la lista de palabras para generar URLs.
            extensions (list, optional): Extensiones para las palabras de la wordlist.
            timeout (int, optional): Tiempo de espera para las solicitudes.
            follow_redirects (bool, optional): Si se deben seguir redirecciones.
            verify_ssl (bool, optional): Si se debe verificar el SSL.
            output_path (str, optional): Directorio para guardar el reporte.
        """
        self.base_url = base_url
        self.wordlist = wordlist
        self.extensions = extensions
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.output_path = output_path
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    async def run_scan(self):
        """Ejecuta el escaneo de las URLs generadas de manera asíncrona.
        """
        urls = self.generate_urls()
        semaphore = asyncio.Semaphore(10)
        async with aiohttp.ClientSession(headers={'User-Agent': self.user_agent}, connector=aiohttp.TCPConnector(ssl=self.verify_ssl)) as session:
            tasks = []
            for url in tqdm(urls, desc="Scanning URLs", unit="url"):
                task = asyncio.create_task(self.fetch_and_log(session, url, semaphore))
                tasks.append(task)
            responses = await asyncio.gather(*tasks)
            self.process_responses(responses)

    async def fetch_and_log(self, session, url, semaphore):
        """Realiza una solicitud HTTP a la URL especificada y registra la respuesta.

        Args:
            session (aiohttp.ClientSession): Sesión HTTP para realizar solicitudes.
            url (str): URL a la que se realizará la solicitud.
            semaphore (asyncio.Semaphore): Semáforo para limitar el número de solicitudes concurrentes.

        Returns:
            tuple: URL, estado de la respuesta y contenido de la respuesta o mensaje de error.
        """
        async with semaphore:
            try:
                print(f"Obteniendo: {url}")
                response = await session.get(url, allow_redirects=self.follow_redirects, timeout=aiohttp.ClientTimeout(total=self.timeout))
                return (url, response.status, await response.text())
            except Exception as e:
                print(f"Error al obtener la url: {url}: {e}")
                return (url, None, str(e))

    def generate_urls(self):
        """Genera una lista de URLs a partir de la base URL y la wordlist.

        Returns:
            list: Lista de URLs generadas.
        """
        urls = []
        with open(self.wordlist, 'r') as file:
            for line in file:
                base = self.base_url.replace("FUZZ", line.strip())
                urls.append(base)
                for ext in self.extensions:
                    urls.append(f"{base}{ext}")
        return urls
    
    def process_responses(self, responses):
        """Procesa las respuestas obtenidas del escaneo y genera un reporte.

        Args:
            responses (list): Lista de respuestas del escaneo (URL, estado, contenido).
        """
        os.makedirs(self.output_path, exist_ok=True)
        report_file = os.path.join(self.output_path, f"report_{urlparse(self.base_url).netloc}.txt")
        with open(report_file, 'w') as file:
            for url, status, content in responses:
                if status and status == 200:
                    file.write(f"{url}\n")

    def start_scan(self):
        """Inicia el proceso de escaneo de manera síncrona.
        """
        print(f"{YELLOW}Comenzando escaneo para: {self.base_url}{RESET}")
        asyncio.run(self.run_scan())
        print(f"{GREEN}Escaneo completado. Revisa el reporte en: {self.output_path}{RESET}")

if __name__ == "__main__":
    # Configuración e inicio del escaneo
    scanner = WebContentDiscovery(
        base_url="http://192.168.138.129:8080/backups/FUZZ",
        wordlist="webcontent.txt",
        follow_redirects=True,
        verify_ssl=False
    )
    scanner.start_scan()
