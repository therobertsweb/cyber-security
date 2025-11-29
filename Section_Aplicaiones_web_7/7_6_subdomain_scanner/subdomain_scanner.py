import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import sys

class SubdomainScanner:
    """Esta clase permite escanear subdominios de un dominio dado utilizando una lista de palabras y opcionalmente una lista de servidores de nombres.

    Attributes:
        domain (str): Dominio objetivo para el escaneo.
        wordlist (list): Lista de palabras para generar subdominios.
        ipv6 (bool): Indica si se deben resolver registros AAAA (IPv6) en lugar de A (IPv4).
        threads (int): Número de hilos a utilizar para el escaneo.
        resolver (dns.resolver.Resolver): Objeto Resolver configurado.
        record_type (str): Tipo de registro DNS a resolver ('A' o 'AAAA').
    """

    def __init__(self, domain, wordlist, resolver_list=None, ipv6=False, threads=10):
        """Inicializa la clase SubdomainScanner con los parámetros especificados.

        Args:
            domain (str): Dominio objetivo para el escaneo.
            wordlist (str): Ruta al archivo de la lista de palabras para generar subdominios.
            resolver_list (str, optional): Ruta al archivo con la lista de servidores de nombres. Defaults to None.
            ipv6 (bool, optional): Indica si se deben resolver registros AAAA (IPv6) en lugar de A (IPv4). Defaults to False.
            threads (int, optional): Número de hilos a utilizar para el escaneo. Defaults to 10.
        """
        self.domain = domain
        self.wordlist = self.load_file(wordlist)
        self.ipv6 = ipv6
        self.threads = threads
        self.resolver = self.setup_resolver(resolver_list)
        self.record_type = 'AAAA' if ipv6 else 'A'

    def load_file(self, path):
        """Carga el contenido de un archivo y lo devuelve como una lista de líneas.

        Args:
            path (str): Ruta al archivo.

        Returns:
            list: Lista de líneas del archivo.

        Raises:
            SystemExit: Si el archivo no se puede abrir.
        """
        try:
            with open(path, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError:
            print(f"Error: No se ha podido abrir el fichero: {path}")
            sys.exit(1)

    def setup_resolver(self, resolver_list):
        """Configura el objeto Resolver con una lista de servidores de nombres opcional.

        Args:
            resolver_list (str, optional): Ruta al archivo con la lista de servidores de nombres. Defaults to None.

        Returns:
            dns.resolver.Resolver: Objeto Resolver configurado.

        Raises:
            SystemExit: Si el archivo de servidores de nombres no se puede abrir.
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        if resolver_list:
            try:
                with open(resolver_list, 'r') as file:
                    resolver.nameservers = file.read().splitlines()
            except FileNotFoundError:
                print(f"Error al leer el fichero con los servidores de nombres: {resolver_list}")
                sys.exit(1)
        return resolver
    
    def scan(self):
        """
        Realiza el escaneo de subdominios utilizando múltiples hilos.
        """
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.scan_domain, self.wordlist))
        self.present_results(results)

    def scan_domain(self, subdomain):
        """Escanea un subdominio específico y resuelve su dirección IP.

        Args:
            subdomain (str): Subdominio a escanear.

        Returns:
            tuple: Tupla con el subdominio completo y una lista de direcciones IP resueltas.
            None: Si no se puede resolver el subdominio.
        """
        full_domain = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(full_domain, self.record_type)
            return (full_domain, [answer.address for answer in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return None
        
    def present_results(self, results):
        """Presenta los resultados del escaneo en la salida estándar.

        Args:
            results (list): Lista de resultados del escaneo.
        """
        if not results or all(result is None for result in results):
            print("No se han encontrado subdominios activos.")
        else:
            print("Resultados del escaneo de subdominios:")
            for result in results:
                if result:
                    domain, addresses = result
                    print(f"Subdominio: {domain}")
                    for address in addresses:
                        print(f"   - IP: {address}")

if __name__ == "__main__":
    scanner = SubdomainScanner(
        domain="udemy.com",
        wordlist="subdomains.txt",
        resolver_list="nameservers.txt",
        ipv6=False,
        threads=10
    )
    scanner.scan()
