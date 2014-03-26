import socket
import select
import sys
import time
import os
from time import sleep

s1=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
hostname=sys.argv[1]
print hostname
s1.bind(hostname)
c=1
while(c):
       d = int(s1.recv(4))
       s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
       count=1
       while (count):

         f=open("test1.txt", "rb")
         l = f.read(1024)
         s.sendto(l,("10.0.0.1",9999))
         t=time.strftime("%S")
         print("%s"%t)
         count=count-1
         time.sleep(d)


       c=0

s.close()
s1.close()
os.remove(hostname)
sys.exit()
