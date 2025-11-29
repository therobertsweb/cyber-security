import socket

def main():
    """Establece un servidor en la dirección y puerto especificados, 
    espera a que un cliente se conecte y permite el envío y recepción de comandos.
    """
    host = '0.0.0.0'
    port = 9999

    # Crear el socket del servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Servidor escuchando en {host}:{port}")

        # Esperar a que un cliente se conecte
        client_socket, addr = server_socket.accept()
        with client_socket:
            print(f"Conexión establecida con {addr}")

            while True:
                command = input("Escribe un comando: ")
                
                # Salir si el comando es 'exit'
                if command.lower() == 'exit':
                    client_socket.send(command.encode())
                    break

                # Enviar comando al cliente
                client_socket.send(command.encode())

                # Recibir respuesta del cliente
                response = client_socket.recv(4096)
                print("Respuesta recibida:")
                print(response.decode())

if __name__ == "__main__":
    main()