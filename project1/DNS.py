import socket
import binascii
import struct
import csv
import redis
from collections import OrderedDict


PORT = 53
time_out = 3
ip_list = []
cachList = []
types = {
    "err":0,
    "A" : 1,
    "NS" : 2,
    "CNAME" : 5,
    "AAAA" : 28,
    "MX":15,
    "TXT":16,
    "SOA":6
}

def find_type(num):
    temp = list(types.items()) 
    res = [key[0] for idx, key in enumerate(temp) if key[1] == num]
    if(len(res)==0):
        return 0
    return str(res[0])

class StreamReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, len_):
        pos = self.pos
        if pos >= len(self.data):
            raise
        res = self.data[pos: pos+len_]
        self.pos += len_
        return res

    def reuse(self, pos):
        pos = int.from_bytes(pos.encode(), 'big')
        return parse_dns_string(None, self.data[pos:])

def create_qname(domain):
    message = ""
    addr_parts = domain.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()
    return message

def get_type(type_):
    st = [k[1] for k in list(types.items()) if k[0]==type_]
    return "{:04x}".format(st[0])


def parse_dns_string(reader, data):
    res = ''
    to_resue = None
    bytes_left = 0

    for ch in data:
        if not ch:
            break
        
        if to_resue is not None:
            resue_pos = chr(to_resue) + chr(ch)
            res += reader.reuse(resue_pos)
            break

        if bytes_left:
            res += chr(ch)
            bytes_left -= 1
            continue

        if (ch >> 6) == 0b11 and reader is not None:
            to_resue = ch - 0b11000000
        else:
            bytes_left = ch

        if res:
            res += '.'
    return res

def make_dns_query(domain,type_):
    ID = 43690  
    QR = 0      #   1bit
    OPCODE = 0  #   4bit
    AA = 0      #   1bit
    TC = 0      #   1bit
    RD = 0      #   1bit
    RA = 0      #   1bit
    Z = 0       #   3bit
    RCODE = 0   #   4bit

    query_params =  str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1 # Number of questions           4bit
    ANCOUNT = 0 # Number of answers             4bit
    NSCOUNT = 0 # Number of authority records   4bit
    ARCOUNT = 0 # Number of additional records  4bit

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    message += create_qname(domain)
    message += "00" # Terminating bit for QNAME
    QTYPE = get_type(type_)
    message+=QTYPE
    QCLASS = 1
    message += "{:04x}".format(QCLASS)
    return message

def add_record_to_result(data, type_,reader):
    ans = ""
    if type_ == "A":
        ans += str(int.from_bytes(data[0:1], 'big')) + "." + str(int.from_bytes(data[1:2], 'big')) + "." + str(int.from_bytes(data[2:3], 'big')) +"." + str(int.from_bytes(data[3:4], 'big'))
    elif type_=="AAAA":
        ip_list= struct.unpack("!HHHHHHHH",data)
        ans += ":".join([format(part,'x') for part in ip_list])
    elif type_=="MX":
        ans += str(struct.unpack('!h', data[0:2])[0])
        ans +=" "
        ans += parse_dns_string(reader,data[2:])
    else:
        ans += parse_dns_string(reader,data)
    return [type_,ans]

def to_int(bytes_):
    return int.from_bytes(bytes_, 'big')

def parse_dns_response(res, req):
    reader = StreamReader(res)
    n = len(req)
    data = reader.read(n)
    result = []
    result_count = to_int(data[6:8])
    authority_count = to_int(data[8:10])
    additional_count = to_int(data[10:12])
    data_count = (result_count,authority_count,additional_count)
    if result_count!=0:
        result.append(parse_middle_data(result_count,reader,"answer"))
    if authority_count!=0:
        result.append(parse_middle_data(authority_count,reader,"authority"))
    if additional_count!=0:
        result.append(parse_middle_data(additional_count,reader,"additional"))
    return (result,data_count)

def parse_middle_data(result_count,reader,type_):
    res = []
    for i in range(result_count):
        reader.read(2)
        type_num = reader.read(2)
        n = to_int(type_num[1:2])
        type_num = find_type(n)
        if(type_num==0):
            print("request record is ", n ,"Can't parse this type")
            continue
        reader.read(6)
        data = reader.read(2)
        data = reader.read(to_int(data))
        res.append(add_record_to_result(data,type_num ,reader))
    return {type_ : res}

def print_result(domain,result,data_count,FW,cache):
    global time_out
    global ip_list
    global cachList
    time_out = 0
    auth_index = 0
    add_index = 0
    str_result ="result count : " + str(data_count[0]) +"\n"
    str_result+="authority count : " + str(data_count[1]) +"\n"
    str_result+="additional count : " + str(data_count[2])
    print(str_result)
    print("=========================================")
    for RDATA in result:
        toppic  = list(RDATA.keys())[0]
        print(toppic)
        if toppic=="answer":
            answer = RDATA.values()
            if cache==True:
                cachList.append(["not",answer])
        if toppic == "additional":
            for ipp in list(RDATA.values()):
                for i in ipp:
                    ip_list.append(i)

        for ip in list(RDATA.values()):
            for i in ip:
                print("type:" , i[0]," - ", i[1])
        print("=========================================")

        # dfs for findinf solution
    while(data_count[0] == 0):
        if len(ip_list)!=0:
            ip = ip_list.pop() 
            if ip[0] == "A" and ip[1]!="193.189.123.2":
                print("another request to",ip[1])
                dns_lookup(domain,ip[1],FW,cache)
                break
        else:
            print("Sorry, no response was founded")
            answer = ["Sorry no response was founded"]
            break

    if (FW and data_count[0]!=0):
        write_in_file(answer)
    elif (FW and answer == ["Sorry no response was founded"]):
        write_in_file(answer)

def dns_lookup(message,address,FW,cache):
    global time_out
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(binascii.unhexlify(message), (address, PORT))
        res, _ = sock.recvfrom(1024 * 4)
        result,data_count = parse_dns_response(res,binascii.unhexlify(message))
        print_result(message,result,data_count,FW,cache)

    except socket.timeout as err:
        print(err,"send another request.")
        time_out+=1
        if time_out==3:
            print("Sorry.can't find result.please try later")
            return
        dns_lookup(message,address,FW,cache)
    except Exception:
        return
    finally:
        sock.close()

def make_massage(domain,type_):
    dns_domain = create_qname(domain)
    domain_len = len(dns_domain)
    message = make_dns_query(domain,type_)
    message = message.replace(" ", "").replace("\n", "")
    return message

def read_from_csv(add,type_):
    with open('domain.csv') as csv_file:
        csv_reader = csv.reader(csv_file)
        for row in csv_reader:
            m = make_massage(row[0],type_)
            dns_lookup(m,add,True)

def write_in_file(data):
    global result_for_write
    result_for_write.append(data)

result_for_write = []

if __name__ == '__main__':
    requestList = []
    domain = ""
    with open("cache.txt","r") as reader:
        tmp = reader.readline()
        while(tmp):
            d_ = tmp.split("-")
            data = [d_[0],d_[1]]
            cachList.append(data)
            tmp = reader.readline()
    
    with open("request.txt","r") as reader:
        tmp = reader.readline()
        while(tmp):
            d_ = tmp.split(",")
            data = [d_[0],int(d_[1])]
            requestList.append(data)
            tmp = reader.readline()

    add = "a.root-servers.net"
    print("1.enter domain")
    print("2.read from csv")
    method = input()
    print("choose record type\nA\nAAAA\nCNAME\nNS\nMX")
    type_ = input()
    isCached = False
    cache = False
    if(method=="1"):
        domain = input("please enter domain:\n")
        for r in cachList:
            if domain == r[0]:
                print(r[1])
                isCached = True
                break
        if isCached==False:
            flag = False
            for r in requestList:
                if domain in r[0]:
                    num = r[1] + 1
                    if(num==3):
                        cache = True
                    if num>3:
                        flag = True
                        break
                    requestList.remove(r)
                    requestList.append([domain,num])
                    flag = True

            if flag==False:
                requestList.append([domain,1])
    
            m = make_massage(domain,type_)
            dns_lookup(m,add,False,cache)
    else:
        read_from_csv(add,type_)
        with open('result.csv', 'w', newline='\n') as csvfile:
            writer = csv.writer(csvfile, delimiter='\n')
            for i in result_for_write:
                print(i)
                writer.writerow(i)

    if isCached==False:
        with open('request.txt', 'w') as writer:
            for req in requestList:
                st = req[0] + "," + str(req[1])+",\n"
                writer.write(st)
        if cache==True:
            with open('cache.txt', 'w') as writer:
                for req in cachList:
                    if req[0] == "not":
                        st = domain + "-" + str((req[1]))+"-\n"
                    else:
                        st = req[0] + "-" + str((req[1]))+"-\n"
                    writer.write(st)
