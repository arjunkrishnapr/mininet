import select
import socket
import sys
import time
import os
from time import sleep

s1=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
hostname=sys.argv[1]
try:
  if os.path.exists(hostname):
     os.remove(hostname)
except OSError:
     pass

print hostname
s1.bind(hostname)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
input=[s1]
c=1
count=1
h=hostname.split("/")[1]

while(c):

   inputready,outputready,execeptready=select.select(input,[],[])
   for i in inputready:

       d = int(i.recv(4))

      # while (count):

#       f=open("test1.txt", "rb")
#       l = f.read(1024)
#       h=hostname.split("/")[1]
#       print h
#       print count
       l = " hello world %s from %s"%((str(count)),h)
       s.sendto(l,("10.0.0.1",9999))
       count = count + 1
#       t=time.strftime("%S")
       print("%s is sending the data"%h)
       #count=count-1
      # time.sleep(d)


      # c=0

s.close()
s1.close()
os.remove(hostname)
sys.exit()
