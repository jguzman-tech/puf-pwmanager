from socket import *
from threading import Thread
import pdb
import pickle
import ast
import random
import argparse
import os
from subprocess import Popen, PIPE
import hashlib

# command-line encrypt and decrypt demo:
# echo "secret message" | openssl rsautl -encrypt -pubin -inkey server_pub.pem | openssl rsautl -decrypt -inkey server_pri.pem

# generate public and private key file:
# prefix=name
# openssl genrsa -out "${prefix}_pri.pem" 2048
# openssl rsa -in "${prefix}_pri.pem" -outform PEM -pubout -out "${prefix}_pub.pem"

# when executing remember to terminate clients first
# otherwise the server socket will have a TIME_WAIT for about 30 seconds while it
# cleans up the connection

def get_hamming_dist(str1, str2):
    result = 0;
    for i in range(len(str1)):
        if(str1[i] != str2[i]):
            result += 1
    print(f"Hamming Distance = {result}")
    return result

def read_puf(memory_grid, hashed_pw, error_rate):
    result = ""
    for i in range(20):
        address = int(hashed_pw[(i * 3):(i * 3 + 3)], 16)
        row = address & 0xFC0 >> 6
        col = address & 0x3F
        elem = memory_grid[row][col]
        if(random.randint(1, 100) <= int(error_rate * 100)):
            if(elem == 0):
                elem = 1
            elif(elem == 1):
                elem = 0
            else:
                raise Exception("Unexpected bit value!")
        result += str(elem)
    return result

def select(address):
    p = Popen(['./select.sh', address], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode().strip()
    return out

def update(address, value):
    p = Popen(['./update.sh', address, value], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode().strip()
    return out

def get_balance(address):
    p = Popen(['./get_balance.sh', address], stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode().strip()
    return out

def update_balance(address, delta):
    p = Popen(['./update_balance.sh', address, delta], stdout=PIPE,
              stderr=PIPE)
    out, err = p.communicate()
    if len(err) > 1:
        return False
    return True

def get_xor(str1, str2):
    num = max(len(str1), len(str2))
    result = ""
    i = 0
    ndx1 = 0
    ndx2 = 0
    while(i < num):
        if(ndx1 == len(str1)):
            ndx1 = 0
        if(ndx2 == len(str2)):
            ndx2 = 0
        x1 = ord(str1[ndx1])
        x2 = ord(str2[ndx2])
        temp = hex(x1 ^ x2)[2:]
        if(len(temp) == 1):
            temp = '0' + temp
        result += temp
        ndx1 += 1
        ndx2 += 1
        i += 1
    return result

def encrypt(client_name, plaintext):
    # need single quotes to avoid expansion in bash
    # use bash to encrypt, convert binary output to hex
    command = f"echo -n '{plaintext}' | "
    command += f"openssl rsautl -encrypt -pubin -inkey {client_name}_pub.pem | "
    command += r"xxd -u -p | tr -d '\n'"
    stream = os.popen(command)
    cyphertext = stream.read()
    return cyphertext

def decrypt(cyphertext):
    # need single quotes to avoid expansion in bash
    # use bash to convert hex to raw binary, decrypt this binary into plaintext
    command = f"echo -n '{cyphertext}' | "
    command += "xxd -r -p | "
    command += "openssl rsautl -decrypt -inkey server_pri.pem"
    stream = os.popen(command)
    plaintext = stream.read()
    return plaintext

def send_to_client(client_socket, client_name, message, generator, do_encrypt):
    if(do_encrypt):
        message = encrypt(client_name, message)
    client_socket.send((message + "\n").encode())
    try:
        response = generator.__next__()
    except:
        # if no response then continue anyway
        response = ""
    if(do_encrypt and len(response) > 0):
        response = decrypt(response)
    return response

def readLines(sock, recv_buffer = 1024, delim='\n'):
    buffer = ''
    data = True

    while data:
        try:
            data = sock.recv(recv_buffer)
        except timeout:
            print('User inactive, closing connection')
            return
        except ConnectionResetError:
            print('Client closed connection')
            return
        except KeyboardInterrupt:
            print('Process ending')
      
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            yield line
    return

def client_handler(client_socket, client_ip, client_port, do_encrypt,
                   memory_grid, error_rate, tolerance):
    print(f'New Connection from {client_ip}:{client_port}')

    g = readLines(client_socket)
    in_msg = g.__next__()
    if(do_encrypt):
        in_msg = decrypt(in_msg)
    client_name = in_msg[0:in_msg.find(" ")]
    password = in_msg[in_msg.find(" "):in_msg.find(":")]
    # address = sha256(uid XOR password), first 12 bits only
    address = str(int(
        hashlib.sha256(
            get_xor(client_name, password).encode()
        ).hexdigest()[0:3], 16))
    # value = PUF(sha256(password)), 20-bit value,
    value = read_puf(memory_grid,
                     hashlib.sha256(password.encode()).hexdigest(),
                     error_rate)
    command = in_msg[in_msg.find(":")+2:]
    if(command == "enroll"):
        # update database
        update(address, value)
        send_to_client(client_socket, client_name, "enrollment success", g,
                       do_encrypt)
    elif(command == "get balance"):
        # check database
        if(get_hamming_dist(select(address), value) <= tolerance):
            send_to_client(client_socket, client_name, "current balance: $" +
                           get_balance(address), g, do_encrypt)
        else:
            send_to_client(client_socket, client_name,
                           "authentication failure, " +
                           "please reconnect and enroll", g, do_encrypt)
    elif(command.find("add") != -1):
        added_funds = command[command.find(" ")+1:]
        if(get_hamming_dist(select(address), value) <= tolerance):
            if update_balance(address, added_funds):
                send_to_client(client_socket, client_name, "new balance: $" +
                               get_balance(address), g, do_encrypt)
            else:
                send_to_client(client_socket, client_name,
                               "failed to add funds, try again",
                               g, do_encrypt)
        else:
            send_to_client(client_socket, client_name, "authentication " +
                           "failure, please reconnect and enroll", g,
                           do_encrypt)
    elif(command.find("withdraw") != -1):
        withdrawal = int(command[command.find(" ")+1:])
        if(get_hamming_dist(select(address), value) <= tolerance):
            if int(get_balance(address)) < withdrawal:
                send_to_client(client_socket, client_name,
                               "insufficient funds", g, do_encrypt)
            else:
                withdrawal = str(-1 * withdrawal)
                if update_balance(address, withdrawal):
                    send_to_client(client_socket, client_name,
                                   "new balance: $" +
                                   get_balance(address), g, do_encrypt)
                else:
                    send_to_client(client_socket, client_name,
                                   "failed to add funds, try again",
                                   g, do_encrypt)
    else:
        send_to_client(client_socket, client_name, "unknown query", g, do_encrypt)
    client_socket.close()

if __name__ == "__main__":
    random.seed(0)
    # this memory_grid will always be the same, the error_rate will be handled
    # by the read_puf function which will take as an arugment a list of int
    # addresses
    memory_grid = list()
    for i in range(64):
        row = list()
        for j in range(64):
            elem = random.randint(0, 1)
            row.append(elem)
        memory_grid.append(row)
            
    parser = argparse.ArgumentParser(description="The server PUF communicator")
    parser.add_argument("port", type=int,
                        help="tcp port number, use 0 to any available port")
    parser.add_argument("-r", "--error-rate", type=float, default=0,
                        help="error rate of PUF")
    parser.add_argument("-t", "--tolerance", type=int, default=0,
                        help="hamming distance threshold")
    parser.add_argument("-e", "--encrypt", dest="encrypt", action="store_true",
                        help="set this option to encrypt all traffic")
    args = parser.parse_args()
    
    print("Server is running...")
    tcp_socket = socket(AF_INET, SOCK_STREAM)
    tcp_socket.bind(('', args.port)) # bound to any IP address, any port
    tcp_port = tcp_socket.getsockname()[1]
    
    print("TCP socket has port number: " + str(tcp_port))
    try:
        while True:
            tcp_socket.listen(0)
            client_socket, client_info = tcp_socket.accept()
            client_ip = client_info[0]
            client_port = client_info[1]
            Thread(target=client_handler,
                   args=(client_socket, client_ip, client_port, args.encrypt,
                         memory_grid, args.error_rate, args.tolerance)).start()
    except KeyboardInterrupt:
        tcp_socket.close()
