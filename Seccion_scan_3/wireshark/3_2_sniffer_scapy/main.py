from sniffer_scapy import SnifferScapy

def main():
    sniffer = SnifferScapy()

    # 1. Leer archivo pcapng
    sniffer.read_capture("wireshark_capture.pcapng")

    # 2. Filtrar paquetes que contengan '443'
    packets = sniffer.filter_by_text('443')

    # 3. Exportar a nuevo archivo .pcap
    sniffer.export_to_pcap(packets, "wireshark_capture_filtered.pcap")

if __name__ == "__main__":
    main()