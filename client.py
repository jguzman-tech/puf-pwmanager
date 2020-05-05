from socket import *
from threading import Thread
import pdb
import os
from subprocess import Popen, PIPE
import argparse
import random
import numpy as np
import ast
import pickle

def encrypt(plaintext):
    # need single quotes to avoid expansion in bash
    command = f"echo -n '{plaintext}' | "
    command += f"openssl rsautl -encrypt -pubin -inkey server_pub.pem | "
    command += r"xxd -u -p | tr -d '\n'"
    stream = os.popen(command)
    cyphertext = stream.read()
    return cyphertext

def decrypt(name, cyphertext):
    # need single quotes to avoid expansion in bash
    command = f"echo -n '{cyphertext}' | "
    command += "xxd -r -p | "
    command += f"openssl rsautl -decrypt -inkey {name}_pri.pem"
    stream = os.popen(command)
    plaintext = stream.read()
    return plaintext

def readLine(sock, recv_buffer = 1024, delim='\n'):
    global buffer
  
    while True:
        data = sock.recv(recv_buffer)
        buffer += data.decode()
        buffer = buffer.replace('\r','')
        while buffer.find(delim) != -1:
            line, buffer = buffer.split('\n',1)
            return line
    return

def send_to_server(tcp_socket, message, name, do_encrypt):
    print(f"sending to server: {message.strip()}")
    if(do_encrypt):
        message = encrypt(message)
    tcp_socket.sendall((message + "\n").encode())
    response = readLine(tcp_socket)
    if(do_encrypt):
        response = decrypt(name, response)
    print(f"received from server: {response}\n")
    return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The client communicator")
    parser.add_argument("server_host", type=str,
                        help="The ip address (or hostname) of the server")
    parser.add_argument("port", type=int,
                        help="server tcp port to connect to")
    parser.add_argument("--encrypt", dest="encrypt", action="store_true",
                        help="set this option to encrypt all traffic")
    args = parser.parse_args()
    
    name = input("Username: ")
    name.replace(" ", "")
    name.replace(":", "")
    password = input("Password: ")
    password.replace(" ", "")
    password.replace(":", "")

    if(os.path.exists(f"{name}_pri.pem") and
       os.path.exists(f"{name}_pub.pem")):
        # user has their key files in the current directory, continue
        pass
    else:
        print("Your public and private key files were not found " +
              "in this directory.")
        response = input("Do you wish to create them now?(yes/no): ")
        response = response.lower()
        if(response == 'yes'):
            command = f"prefix={name};"
            command += "openssl genrsa -out \"${prefix}_pri.pem\" 2048;"
            command += "openssl rsa -in \"${prefix}_pri.pem\" -outform "
            command += "PEM -pubout -out \"${prefix}_pub.pem\""
            stream = os.popen(command)
            stream.read()
            if(os.path.exists(f"{name}_pri.pem") and
               os.path.exists(f"{name}_pub.pem")):
                print("Key file generation success")
            else:
                raise Exception("Unable to generate key files")
        elif(response == 'no'):
            print("Good Bye.")
            exit(0)
        else:
            raise Exception("Invalid Response")
            
    # connect to server here
    global buffer
    buffer = ""
      
    # Get IP address of server via DNS and print it
    host_ip = gethostbyname(args.server_host)
    print("Server IP: " + str(host_ip))

    tcp_port = str(args.port)

    # Check if we have a valid port

    tcp_socket = socket(AF_INET, SOCK_STREAM)
    # display the server's TCP Port number
    # print("Server TCP Port: " + str(tcp_port))
    
    # open a TCP connection to the server.
    try:
        tcp_socket.connect((gethostbyname(host_ip), int(tcp_port.encode('utf-8'))))
        print("Client connected to server!")
    except:
        tcp_socket.close()
        raise Exception("Unable to connect to server")

    try:
        user_entry = input("Actions:\n" +
                           "1. Enroll\n" +
                           "2. Get Balance\n" +
                           "3. Add Funds\n" +
                           "4. Withdraw Funds\n" +
                           "5. Exit\nChoice(1-5): ")
        print()
        if(user_entry == '1'):
            response = send_to_server(tcp_socket,
                                      f"{name} {password}: enroll",
                                      name,
                                      args.encrypt)
            print(f"{response}")
        elif(user_entry == '2'):
            response = send_to_server(tcp_socket,
                                      f"{name} {password}: get balance",
                                      name,
                                      args.encrypt)
            print(f"{response}")
        elif(user_entry == '3'):
            funds = input("How many dollars do you want to add?: ")
            try:
                funds = int(funds)
            except:
                print("That is not a valid int, try again")
            response = send_to_server(tcp_socket,
                                      f"{name} {password}: add {funds}",
                                      name,
                                      args.encrypt)
            print(f"{response}")
        elif(user_entry == '4'):
            funds = input("How many dollars do you want to withdraw?: ")
            try:
                funds = int(funds)
            except:
                print("That is not a valid int, try again")            
            response = send_to_server(tcp_socket,
                                      f"{name} {password}: withdraw {funds}",
                                      name,
                                      args.encrypt)
            print(f"{response}")
        elif(user_entry == '5'):
            print("Good Bye.")
        else:
            tcp_socket.close()
            raise Exception("Invalid Input")

    except KeyboardInterrupt:
        tcp_socket.close()

    tcp_socket.close()
