import socket
import nmap
import dpkt
from tabulate import tabulate

print('Welcome to the program!')
print('Type ServerScan(), NmapScan() or PcapScan() to use a function')
print(" ")

def ServerScan():
    t_host = str(input("Host web address: "))  
    t_ip = socket.gethostbyname(t_host)     # Resolves to it's public IPv4 address

    print("The IP address of this server is " +t_ip)      # Print the IPv4 address
    print("Use port number 999999 to exit searching for ports.")
    while 1:
            t_port = int(input("Enter the port: "))	   
            if t_port == 999999:
                break
            
            try:
                    sock = socket.socket()			
                    res = sock.connect((t_ip, t_port)) # Trying to connect to the port
                    print ("Port {}: Open" .format(t_port))
                    sock.close()
            except:
                    print ("Port {}: Closed" .format(t_port))
    print ("Port scanning is complete!")
    Reminder()

def NmapScan():
    nm = nmap.PortScanner()
    hostad = input("Input IP address: ")
    ports = input("Input port(s), using a - for a range: ")
    nm.scan(hostad, ports) # scans a host's ports 
    nm.command_line()
    nm.scaninfo()
    nm.all_hosts()
    nm[hostad].hostname() # get one hostname for a host
    nm[hostad].hostnames() #get list of hostnames for a host
    print('Current device information')
    #Listing all hosts on the current device
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        # Listing all used protocols on the host
        for proto in nm[host].all_protocols():
            print('----------------------------------------------------')
            print('Protocol : %s' % proto)
            # Looking at active ports and their states and displaying the information
            lport = nm[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

    print('----------------------------------------------------')
    print('Available hosts on your network')

    # Lists reachable hosts on a subnet
    subnetad = input('Input subnet address, in form n.n.n.n/n: ')
    nm.scan(hosts=subnetad, arguments='-n -sP -PE -PA21 23 80 3389 44 322')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print('{0}:{1}'.format(host, status))

    print('----------------------------------------------------')
    print('Nmap scan complete!')
    Reminder()

def printPcap(pcap):
    srcList = []
    destList = []
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # read the source IP in src
            src = socket.inet_ntoa(ip.src)
            srcList.append(src)
            # read the destination IP in dst
            dst = socket.inet_ntoa(ip.dst)
            destList.append(dst)
            # Print the source and destination IP
            print ('Source: ' +src+ ' Destination: '  +dst )
        except:
            pass
    iplist ={srcList[i]: destList[i] for i in range(len(srcList))}
    print('----------------------------------------------------')
    print('There are ' +str(len(iplist)) + ' paths.')
    print("The list of used paths were:")
    headers = ["Source", "Destination"]
    print(tabulate(iplist.items(), headers=headers, tablefmt="github", colalign=("center",)))
    print('----------------------------------------------------')
    print("Pcap scan complete!")
    Reminder()
          
def PcapScan():
	# Open pcap file for reading
	filena = input('Input File name: ')
	print(" ")
	f = open(filena, 'rb')
	#pass the file argument to the pcap.Reader function
	pcap = dpkt.pcap.Reader(f)
	print('The full list of IP adddresses are as followed')
	print('----------------------------------------------------')
	printPcap(pcap)

def Reminder():
    print(" ")
    print('Type ServerScan(), NmapScan() or PcapScan() to use a function')
    print(" ")




