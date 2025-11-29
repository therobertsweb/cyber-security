from auth_session import AuthSession
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import streamlit as st

class SQLIScanner:
    """Escáner de inyecciones SQL (SQLi).

    Attributes:
        session (AuthSession): Sesión autenticada para realizar las solicitudes.
        payloads (list): Lista de payloads de inyección SQL.
        vulnerabilidades (list): Lista de vulnerabilidades encontradas.
    """

    def __init__(self, session, payload_file):
        """Inicializa la clase SQLIScanner.

        Args:
            session (AuthSession): La sesión autenticada.
            payload_file (str): El archivo que contiene los payloads de inyección SQL.
        """
        self.session = session
        self.payloads = self.load_payloads(payload_file)
        self.vulnerabilidades = []

    def load_payloads(self, filename):
        """Carga los payloads desde un archivo.

        Args:
            filename (str): Nombre del archivo que contiene los payloads.

        Returns:
            list: Lista de payloads.
        """
        try:
            with open(filename, 'r') as file:
                return [line.strip() for line in file if line.strip() and not line.startswith('<!--')]
        except IOError as e:
            st.error(f"Error leyendo el fichero {filename}: {e}")
            return []

    def get_all_forms(self, url):
        """Obtiene todos los formularios de una URL.

        Args:
            url (str): URL de la página a analizar.

        Returns:
            list: Lista de formularios encontrados.
        """
        response = self.session.get(url)
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        """Obtiene los detalles de un formulario.

        Args:
            form (bs4.element.Tag): Elemento del formulario.

        Returns:
            dict: Diccionario con los detalles del formulario.
        """
        details = {
            'action': form.attrs.get("action", "").lower(),
            'method': form.attrs.get("method", "get").lower(),
            'inputs': [{'type': input_tag.attrs.get("type", "text"), 'name': input_tag.attrs.get("name")}
                       for input_tag in form.find_all("input")]
        }
        return details

    def submit_form(self, form_details, url, value):
        """Envía un formulario con un valor dado.

        Args:
            form_details (dict): Detalles del formulario.
            url (str): URL base.
            value (str): Valor a enviar en el formulario.

        Returns:
            tuple: Respuesta de la solicitud y la URL explotada.
        """
        target_url = urljoin(url, form_details['action'])
        data = {input['name']: value if input['type'] in ["text", "search"] else input.get("value", "")
                for input in form_details['inputs'] if input['name']}
        if form_details["method"] == "post":
            data['form'] = 'submit'
            response = self.session.post(target_url, data=data)
        else:
            response = self.session.get(target_url, params=data)
        return response, response.url

    def is_vulnerable(self, response):
        """Verifica si una respuesta indica vulnerabilidad.

        Args:
            response (requests.Response): Respuesta de la solicitud.

        Returns:
            bool: Verdadero si es vulnerable, falso de lo contrario.
        """
        if "Invalid credentials".lower() in response.text.lower():
            return False
        return True

    def scan_sqli(self, url):
        """Escanea una URL en busca de vulnerabilidades de inyección SQL.

        Args:
            url (str): URL a escanear.
        """
        forms = self.get_all_forms(url)
        for form in forms:
            form_details = self.get_form_details(form)
            progress_text = st.empty()
            for payload in self.payloads:
                progress_text.text(f"Testing payload: {payload}")
                response, exploit_url = self.submit_form(form_details, url, payload)
                if self.is_vulnerable(response):
                    self.vulnerabilidades.append({
                        'payload': payload,
                        'url': url,
                        'exploit_url': exploit_url,
                        'form_details': form_details
                    })
            progress_text.empty()

    def display_results(self):
        """Muestra los resultados del escaneo."""
        if self.vulnerabilidades:
            st.success(f"Encontradas {len(self.vulnerabilidades)} vulnerabilidades:")
            for vulnerability in self.vulnerabilidades[:100]:
                st.markdown(f"**Payload**: `{vulnerability['payload']}`")
                st.markdown(f"**URL**: {vulnerability['url']}")
                st.markdown(f"**Exploit URL**: {vulnerability['exploit_url']}")
                st.json(vulnerability['form_details'])
        else:
            st.error("No se han encontrado vulnerabilidades.")

def main():
    """
    Función principal para ejecutar la aplicación Streamlit.
    """
    st.title("SQL Injection Scanner")
    base_url = st.text_input("Base URL", "http://192.168.138.129:8080")
    username = st.text_input("Username", "usuario1")
    password = st.text_input("Password", "1234")
    security_level = st.selectbox("Security Level", [0, 1, 2], index=0)
    payload_file = "sqli_payloads.txt"

    session = AuthSession(base_url, username, password, security_level)
    scanner = SQLIScanner(session, payload_file)

    target_url = st.text_input("Target URL", "http://192.168.138.129:8080/sqli_3.php")

    if st.button("Scan for SQL Injection"):
        with st.spinner('Scanning...'):
            scanner.scan_sqli(target_url)
            scanner.display_results()

if __name__ == "__main__":
    main()