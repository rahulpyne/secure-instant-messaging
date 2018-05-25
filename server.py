from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import ciphers, hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import  encrypt_with_shared_key
from utils import  decrypt_with_shared_key
from utils import  encrypt_CTR_with_shared_key
from utils import  decrypt_CTR_with_shared_key
from utils import  decryptTagIvAuth
import socket
import threading
import argparse
import pickle
import base64
import json
import select
import os

###################################################################
# we have SIGN-IN, LIST, QUERY and ERROR packets processed by the server.
# SIGN-IN: Inform the presence of user
# LIST: Request and return the list of signed-in users
# QUERY: Request and return the full username and address list of users for sending message
# ERROR: Inform duplicated username


# class ThreadedServer(object):
#     def __init__(self, host, port):
#         self.host = host
#         self.port = port
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         self.sock.bind((self.host, self.port))

#     def listen(self):
#         self.sock.listen(5)
#         while True:
#             client, address = self.sock.accept()
#             client.settimeout(60)
#             threading.Thread(target = self.listenToClient,args = (client,address)).start()

#     def listenToClient(self, client, address):
#         size = 1024
#         while True:
#             try:
#                 data = client.recv(size)
#                 if data:
#                     # Set the response to echo back the recieved data
#                     response = data
#                     client.send(response)
#                 else:
#                     raise error('Client disconnected')
#             except:
#                 client.close()
#                 return False




def packet_handling(csock, addr):
   while True:
        try:
        #     read, write, err = \
        #         select.select([csock,], [csock,], [], 5)
        #     print read, write, err
        # except select.error:
        #     csock.shutdown(2)
        #     csock.close()
        #     for client in CONNECTION_LIST:
        #         if client[1] == addr:
        #             print client[0] + " disconnected"
        #             CONNECTION_LIST.remove(client)
        #     return
        # try:

        # if fail and CONN_AVAI == True:
        #     csock.close()
        #     for client in CONNECTION_LIST:
        #         if client[1] == addr:
        #             print client[0] + " disconnected"
        #             CONNECTION_LIST.remove(client)
        #     return

            data = csock.recv(1000000)

            # check if the connection is lost!!!
            if data == '':
                csock.close()
                for client in CONNECTION_LIST:
                    if client[1] == addr:
                        print client[0] + " disconnected!!!"
                        CONNECTION_LIST.remove(client)
                return

            if len(data) != 0:
                data = json.loads(data)

                # REQUEST is a SIGN-IN packet
                if data[0] == "signin":
                    VALID = True
                    uname = data[1]
                    udp_port = data[2]

                    for client in CONNECTION_LIST:
                        if client[0] == uname:
                            VALID = False
                            break

                    # check if username is already used
                    if VALID == True:
                        CONNECTION_LIST.append((uname, addr, udp_port))
                        CONN_AVAI = True
                        print('%s is now connected' %uname)
                    else:
                        csock.sendall(json.dumps(["error"]))

                elif data[0] == "LIST_RQT":
                    #session_key
                    session_key = "" #TODO need to finalize the way to retrieve Session key for particular client
                    # REQUEST is a LIST packet
                    encrypted_tag_iv_auth = data[2]
                    client_nonce = data[3]
                    tag,iv,auth = decryptTagIvAuth(encrypted_tag_iv_auth,s_private_key)
                    decrypted_message = decrypt_with_shared_key(session_key,iv,tag,data[1],auth)
                    reply = json.dumps([client_nonce,server_nonce])
                    encrypted_reply,new_tag = encrypt_with_shared_key(session_key,iv,reply,auth)
                    mes = json.dumps(["LIST_CHAL_RQT",encrypted_reply,new_tag]) #Tag goes unencrypted here
                    csock.sendall(mes)

                elif data[0] == "LIST_CHAL_RES":
                    #session_key
                    session_key = "" #TODO need to finalize the way to retrieve Session key for particular client
                    # REQUEST is a LIST packet
                    encrypted_tag_iv_auth = data[2]
                    client_nonce = data[3]
                    tag,iv,auth = decryptTagIvAuth(encrypted_tag_iv_auth,s_private_key)
                    decrypted_message = decrypt_with_shared_key(session_key,iv,tag,data[1],auth)
                    received_nonce = decrypted_message[0]
                    if received_nonce == server_nonce:
                        reply = []
                        for client in CONNECTION_LIST:
                            reply.append(client[0])
                        reply = json.dumps(reply)
                        encrypted_reply,new_tag = encrypt_with_shared_key(session_key,iv,reply,auth)
                        mes = json.dumps(["LIST_RES",encrypted_reply,new_tag]) #Tag goes unencrypted here
                        csock.sendall(mes)
                    else:
                        csock.sendall(json.dumps(["AUTH_ERR"]))

                elif data[0] == "TK_RQT":
                    #session_key
                    session_key = "" #TODO need to finalize the way to retrieve Session key for particular client
                    # REQUEST is a LIST packet
                    encrypted_tag_iv_auth = data[2]
                    client_nonce = data[3]
                    tag,iv,auth = decryptTagIvAuth(encrypted_tag_iv_auth,s_private_key)
                    decrypted_message = decrypt_with_shared_key(session_key,iv,tag,data[1],auth)
                    requesting_client_uname = decrypted_message[0]
                    second_client_uname = decrypted_message[1]
                    requesting_client_nonce = decrypted_message[2]
                    second_client_nonce = decrypted_message[3]

                    #Confirming that the requesting client encrypted nonce matches the nonce sent in the request.
                    if client_nonce == requesting_client_nonce:
                        #shared key for client 1 and client 2
                        shared_client_key = os.random(16)

                        #TODO Need to figure how to get the session key for client B, need to figure how to get tag, iv, auth for client B
                        second_client_session_key = ""
                        ticket_data = [requesting_client_uname, shared_client_key, second_client_nonce]
                        ticket_to_second,sec_tag = encrypt_with_shared_key(second_client_session_key,iv,ticket_data,auth)

                        #Encrypt the iv auth sec_tag, tag using the CTR Mode of encryption using the nonce of second client
                        iv_tag_auth_dump = json.dumps([sec_tag,iv,auth])
                        encrypted_iv_tag_auth_data = encrypt_CTR_with_shared_key(second_client_session_key,iv_tag_auth_dump,second_client_nonce)
                        #Message integrity using hmac
                        h_mac = get_hmac_from_shared_key(second_client_session_key, iv_tag_auth_dump)

                        authenticate_data = [requesting_client_uname,second_client_uname, requesting_client_nonce,second_client_nonce, shared_client_key, ticket_to_second ,encrypted_iv_tag_auth_data , hmac]
                        encrypted_reply,new_tag = encrypt_with_shared_key(session_key, iv,authenticate_data, auth)
                        mes = json.dumps(["TK_RES",encrypted_reply,new_tag]) #Tag goes unencrypted here
                        csock.sendall(mes)
                    else:
                        csock.sendall(json.dumps(["AUTH_ERR"]))

                # REQUEST is a QUERY packet
                elif decrypted_message == "query":
                    reply=json.dumps(["query", CONNECTION_LIST])
                    csock.sendall(reply)

        except Exception as x:
            print "There is something wrong, resuming"

if __name__ == "__main__":

    CONNECTION_LIST=[]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--port", type=int, default = "5550", help="specify the server port")
    args = parser.parse_args()
    server_nonce = os.random(16)

    #TODO need to decide from where to populate the server private key
    s_private_key = ""

    if args.port:
        # sock.bind('', args.sp)
        sock.bind(('0.0.0.0', args.port))
        sock.listen(5)

        print("Server Initialized...")
        print('Chat server started on port : ' + str(args.port))
        while True:

            cli_sock, addr = sock.accept()
            print "Connected to ", addr

            thread = threading.Thread(target = packet_handling, args=(cli_sock, addr))
            thread.start()
