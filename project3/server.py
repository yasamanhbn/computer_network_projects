import json
import time
from socket import *
from ipaddress import ip_address
import re, argparse, threading
from ipaddress import ip_address
from netaddr import IPNetwork
import requests
# ***************************************
bufferSize  = 1024
serverPort = 67
server_ip = "127.0.0.1"
msgFromServer = "Hello UDP Client"
bytesToSend = str.encode(msgFromServer)
reservation_list = []
banned_list = []
gateway = "192.168.1.1"
dns = ["9.7.10.15",	"9.7.10.16","9.7.10.18"]
# ***************************************
IP_list = {}
# start_time = 0
running = True

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
    CHADDR = packet[28:28 + 16 + 192]
    magic_cookie = packet[236:240]
    DHCPoptions = packet[240:]

    return OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, magic_cookie, DHCPoptions


def DHCP_offer(xid, ciaddr, chaddr, magic_cookie, ip):
	OP = bytes([0x02])
	HTYPE = bytes([0x01])
	HLEN = bytes([0x06])
	HOPS = bytes([0x00])
	XID = xid
	SECS = bytes([0x00, 0x00])
	FLAGS = bytes([0x00, 0x00])
	CIADDR = ciaddr
	YIADDR = inet_aton(ip) 													#adresse a donner
	SIADDR = inet_aton(server_ip)
	GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
	CHADDR = chaddr
	DHCPoptions1 = bytes([53, 1, 2])
	DHCPoptions2 = bytes([1 , 4]) + inet_aton(subnet_mask)				# read from json file
	DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(gateway) 				# gateway/router
	DHCPOptions4 = bytes([51 , 4]) + ((lease_time).to_bytes(4, byteorder='big')) 	#IP address lease time
	DHCPOptions5 = bytes([54 , 4]) + inet_aton(server_ip) 				# DHCP server
	DHCPOptions6 = bytes([6, 4 * len(dns)]) 							#DNS servers
	# for i in dns:
		# DHCPOptions6 += i
		
	ENDMARK = bytes([0xff])

	package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + magic_cookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPOptions4 + DHCPOptions5 + DHCPOptions6 + ENDMARK
	return package

def DHCP_ack(xid, ciaddr, chaddr, magicookie, ip):
	OP = bytes([0x02])
	HTYPE = bytes([0x01])
	HLEN = bytes([0x06])
	HOPS = bytes([0x00])
	XID = xid
	SECS = bytes([0x00, 0x00])
	FLAGS = bytes([0x00, 0x00])
	CIADDR = ciaddr 
	YIADDR = inet_aton(ip) 													#adresse a donner
	SIADDR = inet_aton(server_ip)
	GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
	CHADDR = chaddr
	Magiccookie = magicookie
	DHCPoptions1 = bytes([53 , 1 , 5]) 										#DHCP ACK(value = 5)
	DHCPoptions2 = bytes([1 , 4]) + inet_aton(subnet_mask)				# subnet_mask 255.255.255.0
	DHCPoptions3 = bytes([3 , 4 ]) + inet_aton(gateway) 				# gateway
	DHCPoptions4 = bytes([51 , 4]) + ((lease_time).to_bytes(4, byteorder='big')) 	
	DHCPoptions5 = bytes([54 , 4]) + inet_aton(server_ip) 				# DHCP server
	DHCPOptions6 = bytes([6, 4 * len(dns)]) 							# DNS servers
	ENDMARK = bytes([0xff])

	package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + Magiccookie + DHCPoptions1 + DHCPoptions2 + DHCPoptions3 + DHCPoptions4 + DHCPoptions5 + DHCPOptions6 + ENDMARK
	return package


def init_IP(mode, Ip_block, Ip_mask):
	global IP_list
	if mode == "range":
		start = ip_address(Ip_block)
		end = ip_address(Ip_mask)	
		while start <= end:
			# 1:IP address - 2nd: lease time
			p = str(start)
			IP_list[p] = ("null",0,"null")
			start+=1
	elif mode == "subnet":
		network = IPNetwork('/'.join([ip_block, Ip_mask]))
		generator = network.iter_hosts()
		for ip in list(generator):
			# 1:IP address - 2nd: lease time, 3nd: remaining time
			key = str(ip)
			IP_list[key] = ("null",0,"null")


def get_free_ip():						
	global IP_list
	for key, value in IP_list.items() :		
		if(value[0] == "null"):					
			return key
	return False		


def get_ip(mac_address, ip):
	global IP_list
	for key, value in IP_list.items() :		
		if(value[0] == mac_address):				
			return key						

	# if clien't ip request is free, set it.
	if(ip == True):							
		if(IP_list.get(ip)[0] == "null"):		
			return ip 						

	return get_free_ip()	

		
def get_banned_adresses():	
	return banned_list

def ip_addr_format(address):
    return ('{}.{}.{}.{}'.format(*bytearray(address)))

def mac_addr_format(address):
    address = address.hex()[:16]
    return (':'.join(address[i:i+2] for i in range(0,12,2)))

def update_ip(ip, mac_address, lease, init_time = "null"):	
	global IP_list		
	IP_list.update({ip: (mac_address,lease, init_time)})
	return


def clientManage(server, address, packet):
	# global start_time
	# print("new Dosscover message")
	dhcp_client_packet = packet_analyser(packet)
	dhcpoptions = packet_analyser(packet)[13] 												
	dhcpMessageType = dhcpoptions[2]
	dhcpRequestedIp = False
	dest = ('255.255.255.255', address[1])

	# read requested IP address
	for i in range(len(dhcpoptions)):
	    if(dhcpoptions[i:i+2] == bytes([50, 4])):
	        dhcpRequestedIp = ip_addr_format(dhcpoptions[i+2:i+6]) 					

	xid, ciaddr, chaddr, magic_cookie = dhcp_client_packet[4], dhcp_client_packet[7], dhcp_client_packet[11], dhcp_client_packet[12]
	dhcpClientMacAddress = mac_addr_format(chaddr)
	if(dhcpClientMacAddress not in get_banned_adresses()):	
		if(dhcpMessageType == 1): 														
			ip = get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
			if(ip != False):
				# print("send offer")
				data = DHCP_offer( xid, ciaddr, chaddr, magic_cookie, ip)
				server.sendto(data, dest)
			else:
				print("all ips are occupied")

		if(dhcpMessageType == 3):															
			# print("Receive DHCP request.(" + dhcpClientMacAddress + ')')
			ip = get_ip(str(dhcpClientMacAddress), dhcpRequestedIp)
			if(ip != False):
				data = DHCP_ack(xid, ciaddr, chaddr, magic_cookie, ip)
				update_ip(ip, str(dhcpClientMacAddress),lease_time,time.time())
				server.sendto(data, dest)
				# print("send ack message")
				while True:
					current_time = time.time()
					elapsed_time = current_time - IP_list[ip][2]
					if elapsed_time > (IP_list[ip][1]+1):
						update_ip(ip, "null", 0, current_time)
						# print(f"free { ip }")
						break
	else:
		print("this client is banned")
		server.sendto(b"banned", dest)
 
def get_mac_details(mac_address):
	url = "https://api.macvendors.com/"
	response = requests.get(url + mac_address).text
	return response
	# if response.status_code != 200:
	    # raise Exception("[!] Invalid MAC Address!")
	# return response.content.decode()

def stop():
	global running
	running = False

def get_ip_allocated():
	global IP_list
	package = "IP ADDRESSES  |  MAC ADDRESSES  |  Lease time |  Device Name \n----------------------------- \n"
	for key, value in IP_list.items():
		if(value[0] != "null"):
			package += ("(" + key + ") at " + value[0] + '\n')
			if value[2] != "null":
				package += "remaining time: " + str(time.time() - value[2])+'\n'
			else:
				package+= "reserved \n"
			# try:
			vendor_name = get_mac_details(value[0])
			package += "Device vendor is " + vendor_name +'\n'
			# except:
				# package +=	"Device Name: " + "[!] Invalid MAC Address! \n"
				# package +="****************************\n"
	return package

def get_ip_available():
	global IP_list
	package = "IP availables : "
	for key, value in IP_list.items() :
		if(value[0] == "null"):
			package += ("\t(" + key + ") \n")
	return package

def gui():
	global running
	print("[ stop ]	: stop the DHCP server ")
	print("[ usage ] : show ip assignment ")
	print("[ available ] : show ip still available ")
	print("*******************************************************")
	while running:
		request = input(">>Server: ").lower()
		if(request == "stop"):
			stop()

		elif(request == "usage"):
			print(get_ip_allocated())

		elif(request == "available"):
			print(get_ip_available())
	print("DHCP server gui has stoped")

def dhcp_server():
	global running
	server = socket(AF_INET, SOCK_DGRAM)
	server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
	server.bind((server_ip, serverPort))
	while running:
		bytesAddressPair = server.recvfrom(bufferSize)
		packet = bytesAddressPair[0]
		address = bytesAddressPair[1]
		newThread = threading.Thread(target=clientManage, args=(server, address, packet))
		newThread.start()
	print("Bye")


if __name__ == '__main__':
	f = open('config.json')
	data = json.load(f)
	pool_mode = data['pool_mode']

	ip_from = data['range']['from']
	ip_to = data['range']['to']

	ip_block = data['subnet']['ip_block']
	subnet_mask = data['subnet']['subnet_mask']

	lease_time = int(data['lease_time'])

	f.close()

	if pool_mode == "range":
		init_IP(pool_mode,ip_from,ip_to)
	else:
		init_IP(pool_mode,ip_block,subnet_mask)

	for pair in data["reservation_list"]:
		p = data["reservation_list"][pair]
		reservation_list.append(p)
		update_ip(p[1],p[0],0)

	for ban in range(len(data["black_list"])):
		mac = data["black_list"][ban]
		banned_list.append(mac)
	
	server_gui = threading.Thread(target=gui, name='gui')
	server_gui.start()
	dhcp_server()
	server_gui.join()
