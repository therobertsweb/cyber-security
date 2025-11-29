import socket

def create_server_socket(ip, port):
    """Crea y configura un socket servidor para escuchar conexiones entrantes.
    
    Args:
        ip (str): Dirección IP donde el servidor estará escuchando. Usar '0.0.0.0' para todas las interfaces.
        port (int): Puerto a través del cual el servidor aceptará conexiones.

    Returns:
        socket.socket: Objeto de socket configurado.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)  # Configura el máximo de conexiones en cola
    return server_socket

def accept_connections(server_socket):
    """Acepta una conexión entrante en el socket servidor proporcionado.
    
    Args:
        server_socket (socket.socket): El socket del servidor que está escuchando conexiones.
    
    Returns:
        tuple: Socket del cliente y dirección asociada.
    """
    return server_socket.accept()

def main():
    """Función principal para ejecutar el servidor de socket."""
    server_ip = "0.0.0.0"  # Escuchar en todas las interfaces
    server_port = 4242

    server_socket = create_server_socket(server_ip, server_port)
    print(f"Escuchando conexiones en {server_ip}:{server_port}...")

    try:
        client_socket, client_address = accept_connections(server_socket)
        print(f"Conexión recibida de: {client_address}")

        # Ciclo principal para enviar comandos y recibir respuestas
        while True:
            command = input("> ") + "\n"
            client_socket.send(command.encode())  # Envío del comando al cliente
            response = client_socket.recv(1024)  # Recibir respuesta del cliente
            print(response.decode())

    except KeyboardInterrupt:
        print("Cerrando la conexión.")
    finally:
        client_socket.close()  # Cerrar el socket del cliente
        server_socket.close()  # Cerrar el socket del servidor

if __name__ == "__main__":
    main()