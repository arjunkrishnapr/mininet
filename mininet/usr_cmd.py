import socket
import sys,os


Seh=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
#Seh.bind("/home/mininet/external")

Ssimh=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
#Ssimh.bind("/home/mininet/SExternal")

while(1):
    l=raw_input("ndb> ")

    if l=='c' or l=='s' or l=='h' :
        Seh.sendto(str(l),("/home/mininet/master"))
        
    elif l== 'p' or l=='pd' :
        Ssimh.sendto(str(l),("/home/mininet/simhost"))


    elif l.split(" ")[0]=='f' :
  
        x=l.split(" ")[1]
        Seh.sendto(str(x),("/home/mininet/master"))
#        r,addr=Seh.recvfrom(1024)
#        print r
    else :
        Ssimh.sendto(str(l),("/home/mininet/simhost"))
#        k='s'
#        Seh.sendto(str(k),("/home/mininet/master"))
 
Seh.close()
Ssimh.close()
os.remove('/home/mininet/master')
