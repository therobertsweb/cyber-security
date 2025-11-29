import socket
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Any, Optional

# Configuración básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Rich no disponible, usando salida básica")

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy no disponible, algunas funciones no trabajarán")

class NetworkAnalyzer:
    def __init__(self, network_range: str, timeout: int = 1, max_workers: int = 50):
        self.network_range = network_range
        self.timeout = timeout
        self.max_workers = max_workers
        self.console = Console() if RICH_AVAILABLE else None

    def validate_network_range(self) -> bool:
        """Valida que el rango de red sea correcto"""
        try:
            ipaddress.ip_network(self.network_range, strict=False)
            return True
        except ValueError as e:
            logger.error(f"Rango de red inválido: {e}")
            return False

    def _scan_host_sockets(self, ip: str, port: int = 1000) -> Tuple[int, bool]:
        """Escaneo básico con sockets"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                return (port, result == 0)
        except (socket.timeout, socket.error, OSError) as e:
            return (port, False)

    def _scan_host_scapy(self, ip: str, scan_ports: Tuple = (135, 445, 139)) -> Tuple[str, bool]:
        """Escaneo con Scapy si está disponible"""
        if not SCAPY_AVAILABLE:
            # Fallback a sockets si Scapy no está disponible
            for port in scan_ports:
                _, is_open = self._scan_host_sockets(ip, port)
                if is_open:
                    return (ip, True)
            return (ip, False)
        
        try:
            for port in scan_ports:
                packet = IP(dst=ip)/TCP(dport=port, flags='S')
                answered, _ = sr(packet, timeout=self.timeout, verbose=0, retry=0)
                for sent, received in answered:
                    if received.haslayer(TCP) and received[TCP].flags & 0x12:  # SYN-ACK
                        # Enviamos RST para cerrar la conexión
                        rst_pkt = IP(dst=ip)/TCP(dport=port, flags='R')
                        send(rst_pkt, verbose=0)
                        return (ip, True)
        except Exception as e:
            logger.debug(f"Error en escaneo Scapy para {ip}: {e}")
        
        return (ip, False)

    def hosts_scan_arp(self) -> List[str]:
        """Escaneo ARP mejorado"""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy no disponible, no se puede realizar escaneo ARP")
            return []
            
        hosts_up = []
        try:
            network = ipaddress.ip_network(self.network_range, strict=False)
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            
            if TQDM_AVAILABLE:
                answered = tqdm(srp(arp_request, timeout=self.timeout, verbose=0), 
                               desc="Escaneando con ARP")
            else:
                answered, _ = srp(arp_request, timeout=self.timeout, verbose=0)
                
            for _, received in answered:
                hosts_up.append(received.psrc)
        except Exception as e:
            logger.error(f"Error en escaneo ARP: {e}")
            
        return hosts_up

    def hosts_scan(self, scan_ports: Tuple = (135, 445, 139)) -> List[str]:
        """Escaneo de hosts activos"""
        if not self.validate_network_range():
            return []

        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        
        # Crear lista de hosts
        hosts_list = [str(host) for host in network.hosts()]
        
        if TQDM_AVAILABLE:
            hosts_iter = tqdm(hosts_list, desc="Escaneando hosts")
        else:
            hosts_iter = hosts_list
            print("Escaneando hosts...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_host_scapy, host, scan_ports): host 
                for host in hosts_iter
            }
            
            for future in as_completed(futures):
                try:
                    ip, is_up = future.result()
                    if is_up:
                        hosts_up.append(ip)
                except Exception as e:
                    logger.debug(f"Error procesando host: {e}")

        return hosts_up

    def ports_scan_optimized(self, common_ports: bool = True, custom_ports: List[int] = None) -> Dict[str, List[int]]:
        """Escaneo de puertos optimizado"""
        if common_ports:
            # Puertos comunes en lugar de escanear todos
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        elif custom_ports:
            ports_to_scan = custom_ports
        else:
            ports_to_scan = list(range(1, 1001))  # Solo los primeros 1000 puertos por defecto

        active_hosts = self.hosts_scan()
        all_open_ports = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {
                executor.submit(self._scan_ports_batch, ip, ports_to_scan): ip 
                for ip in active_hosts
            }

            if TQDM_AVAILABLE:
                with tqdm(total=len(active_hosts), desc="Escaneando puertos") as pbar:
                    for future in as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            open_ports = future.result()
                            if open_ports:
                                all_open_ports[ip] = open_ports
                        except Exception as e:
                            logger.error(f"Error escaneando puertos en {ip}: {e}")
                        finally:
                            pbar.update(1)
            else:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        open_ports = future.result()
                        if open_ports:
                            all_open_ports[ip] = open_ports
                    except Exception as e:
                        logger.error(f"Error escaneando puertos en {ip}: {e}")

        return all_open_ports

    def _scan_ports_batch(self, ip: str, ports: List[int]) -> List[int]:
        """Escanea un lote de puertos de manera más eficiente"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
            except socket.gaierror:
                break  # Host no disponible
            except Exception:
                continue
        return open_ports

    def get_banner(self, ip: str, port: int) -> Optional[str]:
        """Banner grabbing básico"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                s.send(b'\r\n')
                return s.recv(1024).decode(errors='ignore').strip()
        except Exception as e:
            return None

    def pretty_print(self, data: Any, data_type: str = "hosts"):
        """Método de impresión que funciona con o sin Rich"""
        if not data:
            print("No hay datos para mostrar")
            return

        if self.console and RICH_AVAILABLE:
            self._pretty_print_rich(data, data_type)
        else:
            self._pretty_print_basic(data, data_type)

    def _pretty_print_rich(self, data: Any, data_type: str):
        """Impresión con Rich"""
        table = Table(show_header=True, header_style="bold magenta")
        
        if data_type == "hosts":
            table.add_column("Hosts Activos", style="bold green")
            for host in data:
                table.add_row(host)

        elif data_type == "ports":
            table.add_column("IP Address", style="bold green")
            table.add_column("Open Ports", style="bold blue")
            table.add_column("Count", style="bold red")
            for ip, ports in data.items():
                ports_str = ', '.join(map(str, sorted(ports)))
                table.add_row(ip, ports_str, str(len(ports)))

        elif data_type == "services":
            table.add_column("IP Address", style="bold green")
            table.add_column("Port", style="bold blue")
            table.add_column("Service/Banner", style="bold yellow")
            for ip, services in data.items():
                for port, service in services.items():
                    service_truncated = service[:100] + "..." if len(service) > 100 else service
                    table.add_row(ip, str(port), service_truncated)

        self.console.print(table)

    def _pretty_print_basic(self, data: Any, data_type: str):
        """Impresión básica sin Rich"""
        print(f"\n=== {data_type.upper()} ===")
        
        if data_type == "hosts":
            for host in data:
                print(f"  {host}")

        elif data_type == "ports":
            for ip, ports in data.items():
                print(f"  {ip}: {', '.join(map(str, sorted(ports)))}")

        elif data_type == "services":
            for ip, services in data.items():
                print(f"  {ip}:")
                for port, service in services.items():
                    print(f"    Port {port}: {service}")

        print()

# Ejemplo de uso
if __name__ == "__main__":
    # Ejemplo básico sin SMB
    analyzer = NetworkAnalyzer("192.168.1.0/24", timeout=2, max_workers=30)
    
    if analyzer.validate_network_range():
        print("Iniciando escaneo...")
        
        hosts = analyzer.hosts_scan()
        analyzer.pretty_print(hosts, "hosts")
        
        if hosts:
            ports = analyzer.ports_scan_optimized(common_ports=True)
            analyzer.pretty_print(ports, "ports")
        else:
            print("No se encontraron hosts activos")