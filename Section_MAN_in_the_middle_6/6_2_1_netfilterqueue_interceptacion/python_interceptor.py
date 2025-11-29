from netfilterqueue import NetfilterQueue
from scapy.all import *

def intercept(packet):
    """Esta función es llamada por NetfilterQueue para cada paquete que
    pasa por la cola. Extrae el payload del paquete, lo convierte a un
    paquete IP de Scapy, lo muestra y lo reenvía.

    Args:
        packet (scapy.Packet): El paquete que está siendo procesado.

    """
    payload = packet.get_payload()
    spkt = IP(payload)
    print("[+] Ha llegado un paquete: ")
    spkt.show()
    packet.set_payload(bytes(spkt))
    packet.accept()

def main():
    """
    Configura NetfilterQueue para interceptar los paquetes y llama a la
    función `intercept` para procesarlos. Mantiene la cola en ejecución
    hasta que se interrumpe manualmente.
    """
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, intercept)

    try:
        print("[+] Escaneando paquetes de manera activa...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()