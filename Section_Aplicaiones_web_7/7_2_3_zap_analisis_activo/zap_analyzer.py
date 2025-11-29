import os
import time
from collections import defaultdict
from urllib.parse import urlparse
from dotenv import load_dotenv
from zapv2 import ZAPv2
import streamlit as st

class ZapSpider:
    """
    Clase para manejar el escaneo de una web utilizando OWASP ZAP.

    Attributes:
        target_url (str): URL objetivo para el escaneo.
        zap (ZAPv2): Instancia de la API de ZAP.
    """
    
    RISK_MAPPING = {
        'Informational': 0,
        'Low': 1,
        'Medium': 2,
        'High': 3
    }
    
    def __init__(self, target_url: str):
        """
        Inicializa ZapSpider con la URL objetivo y configura la instancia de ZAP.

        Args:
            target_url (str): URL objetivo para el escaneo.
        
        Raises:
            ValueError: Si no se encuentra la clave de API en las variables de entorno.
        """
        load_dotenv()  # Carga las variables de entorno desde .env
        api_key = os.getenv('ZAP_API_KEY')
        if not api_key:
            raise ValueError("API key no encontrada. Asegúrate de que ZAP_API_KEY está definida en .env")
        
        self.target_url = target_url
        self.zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    def start_spider(self) -> list:
        """
        Inicia el escaneo de araña (spidering) en la URL objetivo.

        Returns:
            list: Lista de resultados del escaneo.
        """
        scan_id = self.zap.spider.scan(self.target_url)
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(2)  # Pausa para reducir la carga de CPU
        return self.zap.spider.results()
    
    def passive_scan(self) -> list:
        """
        Realiza un escaneo pasivo en la URL objetivo.

        Returns:
            list: Lista de alertas generadas por el escaneo pasivo.
        """
        self.zap.pscan.enable_all_scanners()
        self.zap.urlopen(self.target_url)
        while int(self.zap.pscan.records_to_scan) > 0:
            time.sleep(2)
        return self.zap.core.alerts()

    def active_scan(self) -> list:
        """
        Realiza un escaneo activo en la URL objetivo.

        Returns:
            list: Lista de alertas generadas por el escaneo activo.
        """
        self.start_spider()
        scan_id = self.zap.ascan.scan(self.target_url)
        while int(self.zap.ascan.status(scan_id)) < 100:
            time.sleep(2)  # Pausa para reducir la carga de CPU
        return self.zap.core.alerts()

    def display_results(self):
        """
        Muestra los resultados del escaneo en la interfaz de Streamlit.
        """
        st.title('Herramienta de Escaneo Web y Análisis Pasivo')
        operation = st.radio("Elige la operación:", ('Spidering', 'Passive Scan', 'Active Scan'))
        if st.button('Iniciar Operación'):
            try:
                if operation == 'Spidering':
                    results = self.start_spider()
                    st.success('¡Spidering completado con éxito!')
                    self._display_urls(results)
                elif operation == 'Passive Scan':
                    results = self.passive_scan()
                    st.success('¡Escaneo pasivo completado con éxito!')
                    self._display_alerts(results)
                elif operation == 'Active Scan':
                    results = self.active_scan()
                    st.success('¡Escaneo activo completado con éxito!')
                    self._display_alerts(results)
            except Exception as e:
                st.error(f"Error: {str(e)}")

    def _display_urls(self, results: list):
        """
        Muestra las URLs obtenidas del spidering.

        Args:
            results (list): Lista de URLs obtenidas del spidering.
        """
        organized_results = defaultdict(list)
        for url in results:
            path = urlparse(url).path
            if not path.endswith('/'):
                path = '/'.join(path.split('/')[:-1])
            organized_results[path].append(url)
        for path, urls in sorted(organized_results.items()):
            st.subheader(path)
            for url in sorted(urls):
                st.write(f"[{url}]({url})")

    def _display_alerts(self, alerts: list):
        """
        Muestra las alertas generadas por el escaneo.

        Args:
            alerts (list): Lista de alertas generadas por el escaneo.
        """
        alerts_sorted = sorted(alerts, key=lambda x: self.RISK_MAPPING.get(x['risk'], -1), reverse=True)
        for alert in alerts_sorted:
            st.write(f"**{alert['alert']}** - {alert['risk']} Risk")
            st.write(f"URL: {alert['url']}")
            st.write(f"Descripción: {alert['description']}")
            st.write(f"Solución: {alert['solution']}")

if __name__ == "__main__":
    target_url = st.text_input('Introduce la URL para escanear:', 'http://192.168.138.129:8899/reflected_xss.php')
    spider = ZapSpider(target_url)
    spider.display_results()