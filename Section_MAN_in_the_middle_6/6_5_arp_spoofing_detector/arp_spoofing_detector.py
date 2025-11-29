from scapy.all import ARP, Ether, srp, sniff
import logging

class ARPSpoofingDetector:
    """Clase para detectar ataques de ARP Spoofing en la red."""

    def __init__(self):
        """Inicializa el detector configurando el logging para mostrar mensajes de alerta."""
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def obtener_mac(self, ip):
        """Obtiene la dirección MAC correspondiente a una IP proporcionada.

        Args:
            ip (str): La dirección IP para la cual se quiere obtener la dirección MAC.

        Returns:
            str: La dirección MAC correspondiente a la IP proporcionada.

        Raises:
            IndexError: Si no se puede obtener la dirección MAC para la IP proporcionada.
        """
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        resultado = srp(paquete, timeout=3, verbose=False)[0]
        try:
            return resultado[0][1].hwsrc
        except IndexError:
            raise IndexError("No se pudo obtener la dirección MAC para la IP proporcionada.")
        
    def procesar_paquete(self, paquete):
        """Procesa un paquete capturado y detecta posibles ataques de ARP Spoofing.

        Args:
            paquete (scapy.packet.Packet): El paquete capturado por Scapy.
        """
        if paquete.haslayer(ARP) and paquete[ARP].op == 2:
            try:
                mac_real = self.obtener_mac(paquete[ARP].psrc)
                mac_respuesta = paquete[ARP].hwsrc
                if mac_real != mac_respuesta:
                    logging.warning(f"[ALERTA] Estás bajo un ataque ARP Spoofing. MAC REAL: {mac_real}, MAC FALSA: {mac_respuesta}")
            except IndexError:
                logging.error("Error al intentar obtener la MAC real, posible IP falsa o problemas de red.")

    def iniciar_deteccion(self):
        """Inicia la detección de ataques de ARP Spoofing capturando paquetes en la red."""
        sniff(store=False, prn=self.procesar_paquete)


if __name__ == "__main__":
    detector = ARPSpoofingDetector()
    detector.iniciar_deteccion()