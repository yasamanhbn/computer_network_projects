from cryptography.fernet import Fernet
import os
import pymongo
from socket import *
from _thread import *
import ssl
import threading
import time
import base64


# ----------------------------------------------------server side--------------------------------------
def manage_message(s_socket,data_p2p):
    res_message = 'I recieved your message'
    m = ''
    for d in data_p2p:
        m +=  d +" "
    print("from my friend:  " + m)
    s_socket.send(res_message.encode('utf-8'))

def manage_exec(conn,data):
    m = ''
    for d in data:
        m +=  d +" "
    result = os.popen(m).read()
    conn.send(result.encode('utf-8'))

def manage_upload(conn,data):
    filename = ''
    for d in data:
        filename +=  d +" "
    print("from my friend: " + filename)
    myfile = open(filename, "rb")
    format_ = (filename.split('.'))[-1]
    conn.send(format_.encode('utf-8'))
    print("sending ...")
    l = myfile.read()
    conn.send(l)
    myfile.close()

def manage_encrypted(conn,e_data):
    b = str.encode(e_data)
    key = conn.recv(1024)
    fernet = Fernet(key)
    decMessage = fernet.decrypt(b).decode()
    print("from my friend:  " + decMessage)
    res_message = 'I recieved your message'
    conn.send(res_message.encode('utf-8'))
    
def telnet_server(HOST,PORT):
    upload_socket = socket()
    host = gethostname()
    upload_socket.bind((HOST,PORT))
    upload_socket.listen(5)
    c, addr = upload_socket.accept()
    while True:
        data_p2p_undecode = c.recv(1024)
        data_p2p = data_p2p_undecode.decode('utf-8')
        if data_p2p=='exit':
            c.close()
            break
        split_data = data_p2p.split(' ')
        if split_data[1] == 'send' and split_data[2] == '-e':
            manage_encrypted(c,split_data[3])
        elif split_data[1] == 'send':
            manage_message(c,split_data[2:])
        elif split_data[1] == 'upload':
            manage_upload(c,split_data[2:])
        elif split_data[1] == 'exec':
            manage_exec(c,split_data[2:])   


# ---------------------------------------client side -----------------------------------------------
count = 1
# check whether port is open or not
def pscan(ip,port):
    with socket(AF_INET, SOCK_STREAM) as s:
        s.settimeout(3)
        con = s.connect_ex((ip,port))
        if(con == 0) :
            print ('Port %d: OPEN' % (port,))
        s.close()
# this method make an ip range and check their open ports
def scan():
    target = input("Enter the host to be scanned: ")
    net = gethostbyname(target)
    print(net)
    net1 = net.split('.')
    a = '.'
    end = input("Enter the Last IP address: ")
    fIP = int(input('input first port range :  '))
    sIP = int(input('input last port:  '))
    end1 = end.split('.')
    ipp0 = 0
    ipp1 = 0
    ipp2 = 0
    ipp3 = 0
    while True:
        ip = str(int(net1[0]) + ipp3) + "." + str(int(net1[1]) + ipp2) + "." + str(int(net1[2]) + ipp1) + "." + str(int(net1[3]) + ipp0)
        print("scan open port for " + ip)
        for p in range(fIP,sIP):
            pscan(ip,p)
        net_p = ip.split(".")
        if net_p[0]>=end1[0] and net_p[1]>=end1[1] and net_p[2]>=end1[2] and net_p[3]>=end1[3]:
            break
        ipp0+=1
        if ipp0 ==255:
            ipp0 = 0 
            ipp1+=1
            if ipp1 ==255:
                ipp1 = 0
                ipp2+=1
                if ipp2 ==255:
                    ipp2 = 0
                    ipp3+=1
    print("finished")

# send email
def send_email():
    msg = "\r\n I love computer networks!"
    endmsg = "\r\n.\r\n"
    mailserver = ("aut.ac.ir", 25)
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(mailserver)
    recv = clientSocket.recv(1024)
    recv = recv.decode()
    print("Message after connection request:" + recv)
    if recv[:3] != '220':
        print('220 reply not received from server.')
    heloCommand = 'EHLO \r\n'
    clientSocket.send(heloCommand.encode())
    recv1 = clientSocket.recv(1024)
    recv1 = recv1.decode()
    print("Message after EHLO command:" + recv1)
    if recv1[:3] != '250':
        print('250 reply not received from server.')

    #Info for username and password
    username = "y.haghbin@aut.ac.ir"
    password = "y13781107"
    base64_str = ("\x00"+username+"\x00"+password).encode()
    base64_str = base64.b64encode(base64_str)
    authMsg = "AUTH PLAIN ".encode()+base64_str+"\r\n".encode()
    clientSocket.send(authMsg)
    recv_auth = clientSocket.recv(1024)
    print(recv_auth.decode())

    mailFrom = "MAIL FROM:<y.haghbin@aut.ac.ir>\r\n"
    clientSocket.send(mailFrom.encode())
    recv2 = clientSocket.recv(1024)
    recv2 = recv2.decode()
    print("After MAIL FROM command: "+recv2)
    rcptTo = "RCPT TO:<y.haghbin@aut.ac.ir>\r\n"
    clientSocket.send(rcptTo.encode())
    recv3 = clientSocket.recv(1024)
    recv3 = recv3.decode()
    print("After RCPT TO command: "+recv3)
    data = "DATA\r\n"
    clientSocket.send(data.encode())
    recv4 = clientSocket.recv(1024)
    recv4 = recv4.decode()
    print("After DATA command: "+recv4)
    subject = "Subject: testing my client\r\n\r\n" 
    clientSocket.send(subject.encode())
    date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    date = date + "\r\n\r\n"
    clientSocket.send(date.encode())
    clientSocket.send(msg.encode())
    clientSocket.send(endmsg.encode())
    recv_msg = clientSocket.recv(1024)
    print("Response after sending message body:"+recv_msg.decode())
    quit = "QUIT\r\n"
    clientSocket.send(quit.encode())
    recv5 = clientSocket.recv(1024)
    print(recv5.decode())
    clientSocket.close()

# send encrypted message
def encrypt_message(HOST,sock,s_data):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    en_data = ''
    for m in s_data[3:]:
        en_data+=m+" "
    encMessage = fernet.encrypt(en_data.encode())
    message = s_data[0]+" "+s_data[1]+" "+s_data[2]+" "+str(encMessage)[2:-1]
    print(message)
    sock.send(message.encode('utf-8'))
    sock.send(key)

# download file
def downloadFile(sock):
    global count
    d = ''
    format_= sock.recv(10)
    with open('./download/' + str(count) +'.'+format_.decode('utf-8'), 'wb') as f:
        print('receiving data...')
        data = sock.recv(1024 * 4)
        f.write(data)
        print('download completed')
    count+=1


def telent_client(HOST, PORT):
    s= socket(AF_INET, SOCK_STREAM)
    s.connect((HOST, PORT))
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["university"]
    name = "netp"+str(HOST)+str(PORT)
    mycol = mydb[name]
    # mycol.drop()
    print("connection starts:")
    while True:
        req = input()
        s_data = req.split(' ')
        if req=='exit':
            s.send(req.encode('utf-8'))
            s.close()
            break
        if s_data[0]!='telnet':
            if PORT == 80 and req=='GET':
                req = "GET / HTTP/1.1\r\nHost:"+HOST+"\r\n\r\n"
            s.send(req.encode('utf-8'))
            data = s.recv(1024)
            print(data.decode('utf-8'))
            continue
        elif s_data[1] != 'history':
            mydict = { "command": req}
            x = mycol.insert_one(mydict)          
        if s_data[1] == 'upload':
            s.send(req.encode('utf-8'))
            downloadFile(s)
        elif s_data[1] == 'send' and s_data[2]=='-e':
            encrypt_message(HOST,s,s_data)
        elif s_data[1] == 'history':
            for x in mycol.find({},{"_id": 0,"command":1}):
                print(x['command'])
        else:
            s.send(req.encode("utf-8"))
            data = s.recv(1024)
            print("from server: "+data.decode("utf-8"))

def client_choice():
    my_host = input("which is my host? ")
    my_port = int(input("which is my port? "))
    s = threading.Thread(target=telnet_server, args=(my_host,my_port))
    s.start()
    my_friends_host = input("what is your friend's host? ")
    my_friends_port = int(input("what is your friend's port? "))
    c = threading.Thread(target=telent_client, args=(my_friends_host ,my_friends_port))
    c.start()


if __name__ == "__main__":
    print("1. scan ports and IP")
    print("2. connect to  my friend")
    print("3.connect to mail server and send mail")
    choice = input()
    if choice =='1':
        scan()
    elif choice =='2':
        client_choice()
    elif choice=='3':
        send_email()
    else:
        print("invalid choice")