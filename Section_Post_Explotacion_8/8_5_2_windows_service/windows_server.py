import socket

def main():
    """Función principal que inicia el servidor y maneja la comunicación con el cliente.
    
    Crea un socket del servidor que escucha en todas las interfaces en el puerto 9999. 
    Acepta conexiones entrantes y permite enviar comandos y recibir respuestas desde el cliente.
    """
    host = "0.0.0.0"
    port = 9999

    # Crear un socket TCP/IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Servidor escuchando en {host}:{port}...")

        # Aceptar una conexión entrante
        client_socket, addr = server_socket.accept()

        # Manejar la conexión con el cliente
        with client_socket:
            print(f"Conexión establecida con: {addr}")

            while True:
                command = input("Escribe un comando: ")
                if command.lower() == 'exit':
                    client_socket.send(command.encode())
                    break

                client_socket.send(command.encode())
                response = client_socket.recv(4096)
                print("Respuesta recibida:")
                print(response.decode())
            
        server_socket.close()

if __name__ == "__main__":
    main()
