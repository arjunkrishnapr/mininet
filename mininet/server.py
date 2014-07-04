import select
import socket
import sys
import time

print "server exe"
#x=socket.gethostbyname(socket.gethostname())
#print x
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("",9999))
input = [server]
running = 1
while running:
    inputready,outputready,exceptready = select.select(input,[],[])

    for s in inputready:

               l,addr = s.recvfrom(1024)
               t=time.strftime("%X")
               x=addr[0]
               sys.stdout.write(l)
               sys.stdout.write(" with IP %s"%(str(x)))
               sys.stdout.write(" (time = %s) " %t)

               print "\n"
               f=open("packet.txt","a")
               f.write(l)
               f.write(" with IP %s"%(str(x)))
               f.write(" (time = %s) " %t )

               f.write("\n")
 
#    running=running-1

server.close()
sys.exit()

