import socket, uuid
import random
import threading
import time

# *****************************************
Ack_timeout = 0
backoff_cutoff = 15
initial_interval = 5
# client_port = 20000
client_port = 20001
# client_port = 20000
# client_port = 20002
raw_mac_addr = 152515438414228
# raw_mac_addr = uuid.getnode()
# raw_mac_addr = 152515428488230
# raw_mac_addr = 152515438414228
# raw_mac_addr = 132505428487228
# raw_mac_addr = 102915428488230
# reserved - ban
# raw_mac_addr = 20754452752546
# reserve mac:"54853259467953" - "54853044509874"
# baned mac: "20754452752546" - "140702351788121"

server_port = 67
bufferSize = 1024
myIP = None
expire_time = 5
start_time = 0
lease_time = 10000
dest = ('255.255.255.255',server_port)
# ******************************************

def packet_analyser(packet):
    OP = packet[0]
    HTYPE = packet[1]   
    HLEN = packet[2]
    HOPS = packet[3]
    XID = packet[4:8]
    SECS = packet[8:10]
    FLAGS = packet[10:12]
    CIADDR = packet[12:16]
    YIADDR = packet[16:20]
    SIADDR = packet[20:24]
    GIADDR = packet[24:28]
    CHADDR = packet[28:28 + 16 +  192]
    magic_cookie = packet[236:240]
    DHCPoptions = packet[240:]

    return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions

def DHCPDiscover():
    OP = bytes([0x01])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = bytes([0x39, 0x03, 0xF3, 0x26])  # random
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    ClientIPADDR = bytes([0x00, 0x00, 0x00, 0x00])
    YourIPADDR = bytes([0x00, 0x00, 0x00, 0x00])
    ServerIPADDR = bytes([0x00, 0x00, 0x00, 0x00]) 
    GatewayIPADDR = bytes([0x00, 0x00, 0x00, 0x00])
    ClientHardwareADDR1 = bytes.fromhex(hex(raw_mac_addr)[2:10])
    ClientHardwareADDR2 = bytes.fromhex(hex(raw_mac_addr)[10:14]) + bytes([0x00, 0x00])
    ClientHardwareADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
    ClientHardwareADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
    ClientHardwareADDR5 = bytes(192)
    Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
    DHCPOptions1 = bytes([53 , 1 , 1])
    DHCPOptions2 = bytes([50 , 4 ]) + socket.inet_aton('192.168.1.100')
    ENDMARK = bytes([0xff])
    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + ClientIPADDR + YourIPADDR + ServerIPADDR + GatewayIPADDR + ClientHardwareADDR1 + ClientHardwareADDR2 + ClientHardwareADDR3 + ClientHardwareADDR4 + ClientHardwareADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + ENDMARK

    return package


def DHCPRequest(xid, yiaddr, siaddr, chaddr,magic_cookie):
    OP = bytes([0x01])
    HTYPE = bytes([0x01])
    HLEN = bytes([0x06])
    HOPS = bytes([0x00])
    XID = xid
    SECS = bytes([0x00, 0x00])
    FLAGS = bytes([0x00, 0x00])
    CIADDR = bytes([0x00, 0x00, 0x00, 0x00]) #Your IP address #Client IP address
    YIADDR = yiaddr #Your IP address
    SIADDR = siaddr #Server IP address
    GIADDR = bytes([0x00, 0x00, 0x00, 0x00]) #Gateway IP address
    CHADDR = chaddr #Client hardware address
    Magiccookie = magic_cookie
    DHCPOptions1 = bytes([53 , 1 , 3]) #DHCP Request
    DHCPOptions2 = bytes([50 , 4 ]) + CIADDR
    DHCPOptions3 = bytes([54 , 4 , 0xC0, 0xA8, 0x01, 0x01]) #DHCP server
    ENDMARK = bytes([0xff])
    package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + ENDMARK
    return package


def ip_addr_format(address):
    address = '{}.{}.{}.{}'.format(*bytearray(address))
    return address


def mac_addr_format(adress):
    adress = adress.hex()[:16]
    adress = ':'.join(adress[i:i+2] for i in range(0,12,2))
    return adress


def info_pack(packet): #get final information from DHCPACK
    global myIP
    global lease_time
    print("XID : " + str((packet[4:8]).hex())) #XID
    print("IPV4 : " + ip_addr_format(packet[16:20])) #YIADDR
    print("MAC ADDR : " + mac_addr_format(packet[28:236])) #CHADRR
    print("ROUTER : " + ip_addr_format(packet[20:24])) #SIADDR
    print("IP address lease time : " + str(int.from_bytes(packet[257:261], "big"))  + "secs") #BAIL    
    myIP = ip_addr_format(packet[16:20])
    lease_time = int.from_bytes(packet[257:261], "big")

def DHCPDiscover_send(sock):
    discoverMessage = DHCPDiscover()
    sock.sendto(discoverMessage,dest)
    try:
        bytePairs = sock.recv(bufferSize)
        return bytePairs
        
    except socket.timeout as err:
        return


def request_management(sock):
    global start_time

    sock.settimeout(5)
    packet = DHCPDiscover_send(sock)
    if packet==b"banned":
        print("banned")
        return
    if packet == None:
        return
    print("Receive DHCP offer.")
    packet_analysed = packet_analyser(packet)
    xid, yiaddr, siaddr, chaddr, magic_cookie = packet_analysed[4], packet_analysed[8], packet_analysed[9], packet_analysed[11], packet_analysed[12]

    print("Send DHCP request.")
    data = DHCPRequest(xid, yiaddr, siaddr, chaddr, magic_cookie)
    sock.sendto(data, dest)
    
    try:
        data, address = sock.recvfrom(bufferSize)   
        print("Receive DHCP ack.")
        start_time = time.time()
        info_pack(data)

    except socket.timeout as err:
        print("timeout: send another Discover")
        DHCPDiscover_send(sock)
        return


def DHCP_timer_request(sock):
    global initial_interval
    global backoff_cutoff
    global myIP
    global start_time
    start_time = time.time()
    while True:
        current_time = time.time()
        elapsed_time = current_time - start_time
        if elapsed_time > initial_interval and myIP==None:
            if initial_interval != backoff_cutoff:
                print(initial_interval)
                initial_interval = 2 * initial_interval * random.uniform(0,1)

            if initial_interval > backoff_cutoff:
                initial_interval = backoff_cutoff

            print(f"haven't got IP:{elapsed_time} - send another request")
            start_time = time.time()

            timer_thread = threading.Thread(target=request_management, args=(sock,))
            timer_thread.start()

        elif myIP!=None and elapsed_time>=lease_time:
            print(f"expire lease time:{elapsed_time} - send another request")      
            start_time = time.time()
            timer_thread = threading.Thread(target=request_management, args=(sock,))
            timer_thread.start()
            

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('127.0.0.1', client_port))
    timer_thread = threading.Thread(target=request_management, args=(s,))
    timer_thread.start()
    DHCP_timer_request(s)
    
