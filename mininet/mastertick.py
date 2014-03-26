import socket,os
import sys
import time
from time import sleep


n=int(sys.argv[1])
#print n
s=[]
HN=[]
l=4
k=2
'''for i in range(1,n-1):
  name='"/hostnew%s"'%i
  HN.append(name)'''

#print HN[0]
#print HN[1]

for i in range(0,n-2):
  s.append(socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM))


#for i in range(0,n-2):
 # s[i].sendto(str(l),("/hostnew%s"%(i+1)))

#for i in range(0,n-2):
 # s[i].close()

sm=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
   

c=1
while(c):
   
 count=6
 while(count):
  # sm=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    print("*** Sending Tick ***")
    for i in range(0,n-2):
      s[i].sendto(str(l),("/hostnew%s"%(i+1)))

    print("*** Sent to hosts ***")
    sm.sendto(str(k),("/simhost"))
    print("*** Sent to simhost ***")
    count-=1
    time.sleep(1)
  #k=k+2
 c=0

sm.close()
os.remove('/simhost')


for i in range(0,n-2):
  s[i].close()
