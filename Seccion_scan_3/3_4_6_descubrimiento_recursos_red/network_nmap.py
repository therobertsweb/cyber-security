import subprocess
import json

def scan_with_nmap(target):
    # -sV: detección de servicios
    # -oX -: salida en XML por stdout
    cmd = ["nmap", "-sV", "-oX", "-", target]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error al ejecutar nmap:", result.stderr)
        return None

    # Aquí podrías parsear el XML a JSON con alguna librería como xmltodict
    return result.stdout

if __name__ == "__main__":
    xml_output = scan_with_nmap("192.168.64.1/24")
    print(xml_output)