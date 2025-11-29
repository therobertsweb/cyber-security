import os
import time
from collections import defaultdict
from urllib.parse import urlparse
import streamlit as st
from dotenv import load_dotenv
from zapv2 import ZAPv2


class ZapAnalyzer:
    """
    Clase para analizar una URL objetivo utilizando OWASP ZAP.

    Args:
        target_url (str): La URL objetivo para el análisis.
    """

    def __init__(self, target_url):
        """
        Inicializa la instancia de ZapAnalyzer.

        Carga las variables de entorno desde un archivo .env y configura la instancia de ZAPv2 con la API key.

        Args:
            target_url (str): La URL objetivo para el análisis.

        Raises:
            ValueError: Si no se encuentra la API key en las variables de entorno.
        """
        load_dotenv()  # Carga las variables de entorno desde .env
        api_key = os.getenv('ZAP_API_KEY')
        if not api_key:
            raise ValueError("API key no encontrada. Asegúrate de que ZAP_API_KEY está definida en .env")

        self.target_url = target_url
        self.zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    def start_spider(self):
        """
        Inicia el proceso de spidering en la URL objetivo.

        Returns:
            list: Una lista de URLs descubiertas durante el spidering.
        """
        scan_id = self.zap.spider.scan(self.target_url)
        while int(self.zap.spider.status(scan_id)) < 100:
            time.sleep(2)  # Espera hasta que el spider complete
        return self.zap.spider.results()

    def display_results(self):
        """
        Lanza una aplicación Streamlit para visualizar interactivamente los resultados del spidering.
        """
        st.title('Web Spidering Tool')
        if st.button('Start Spidering'):
            try:
                results = self.start_spider()
                st.success('Spidering completado satisfactoriamente!')
                organized_results = defaultdict(list)

                for url in results:
                    parsed_url = urlparse(url)
                    path = parsed_url.path
                    if not path.endswith('/'):
                        path = '/'.join(path.split('/')[:-1])  # Organiza por directorio
                    organized_results[path].append(url)

                for path, urls in sorted(organized_results.items()):
                    st.subheader(path)
                    for url in sorted(urls):
                        st.write(f"[{url}]({url})")

            except Exception as e:
                st.error(f"Error: {str(e)}")


if __name__ == "__main__":
    target_url = st.text_input('Introduce la URL:', 'http://192.168.138.129:8899/reflected_xss.php')
    spider = ZapAnalyzer(target_url)
    spider.display_results()