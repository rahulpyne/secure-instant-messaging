from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import ciphers, hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from utils import  encrypt_with_shared_key
from utils import  decrypt_with_shared_key
from utils import  encrypt_CTR_with_shared_key
from utils import  decrypt_CTR_with_shared_key
from utils import load_private_key
from utils import load_public_key
from utils import get_hmac_from_shared_key
from utils import verify_hmac_with_shared_key
import socket
import threading
import argparse
import time
import json
import random
import pyDH

###################################################################
# we have SIGN-IN, LIST, QUERY, MESSAGE and ERROR packets processed by the client.
# SIGN-IN: Inform the presence of user
# LIST: Request the list of signed-in users
# QUERY: Request the full username and address list of users for sending message
# MESSAGE: Send the chat to desired user
# ERROR: Inform duplicated username


def send(server_ip, server_port):
    while True:
        # close the thread if duplicate or lose connection
        global DUPLICATE
        if DUPLICATE ==1:
            sock.close()
            return

        msg = raw_input('+> ')

        if msg == "list":
            send_encrypted_message_to_server("LIST_RQT",[args.user],sock) #TODO is it necessary to send arg.user here?

        if msg[0:5] == "send ":
            # try:
            chat = ""
            name = ""
            info = msg[5:]
            for i in range(len(info)):
                if info[i] == " ":
                    name = info[0:i]
                    chat = info[i+1:]
                    break

            IN_LIST = False

            for client in CONNECTION_LIST:
                if client[0] == name:
                    ccsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ccsock.connect((client[1][0],client[2]))
                    mes = json.dumps(["MES_REQ"])
                    ccsock.sendall(mes)
                    ccsock.close()
                    IN_LIST = True
                    break

            if IN_LIST == False:
                while True:
                    mes = json.dumps(["query"])
                    sock.sendall(mes)
                    time.sleep(2)

                    for client in CONNECTION_LIST:
                        if client[0] == name:
                            ccsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            ccsock.connect((client[1][0],client[2]))
                            mes = json.dumps(["message", args.user, chat])
                            ccsock.sendall(mes)
                            ccsock.close()
                            break
                    break


            # except Exception as x:
            #     print "Something is wrong with your request. Please try again"


def receive(server_ip, server_port):
    while True:
        # try:
        # close the thread if duplicate or lose connection
        global DUPLICATE
        if DUPLICATE == 1:
            sock.close()
            return

        data = sock.recv(1000000)

        # check if the connection is lost!!!
        if data == '':
            sock.close()
            print "The server is down!!!"
            return

        if len(data) != 0:
            data = json.loads(data)

            if data[0] == "LIST_CHAL_RQT":
                server_tag = data[2]
                decrypted_message = decrypt_with_shared_key(session_key,iv,server_tag,data[1],auth)
                `#Response for List Request
                client_nonce = decrypted_message[0]
                server_nonce = decrypted_message[1]
                if client_nonce == nonce:
                    reply = [server_nonce]
                    send_encrypted_message_to_server("LIST_CHAL_RES",reply,sock)
            #Response for List Request
            elif data[0] == "LIST_RES":
                server_tag = data[2]
                decrypted_message = decrypt_with_shared_key(session_key,iv,server_tag,data[1],auth)
                usr = ""
                for d in decrypted_message:
                    usr += d + ", "
                print("\n" + "<-" + " Signed In Users: " + usr)

            #Response for TK_RES packet
            elif data[0] == "TK_RES":
                server_tag = data[2]
                decrypted_message = decrypt_with_shared_key(session_key,iv,server_tag,data[1],auth)
                client_name = decrypted_message[0]
                second_client_uname = decrypted_message[1]
                client_nonce = decrypted_message[2]
                second_client_nonce = decrypted_message[3]
                shared_key = decrypted_message[4]
                ticket_to_second = decrypted_message[5]
                encrypted_iv_tag_auth_data = decrypted_message[6]
                hmac = decrypted_message[7]
                if client_name == args.user and client_nonce == nonce:
                    ccsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ccsock.connect((client[1][0],client[2]))
                    mes = json.dumps([d1_pubkey,nonce])
                    encrypted_data, tag = encrypt_with_shared_key(shared_key, iv, mes, auth)
                    mes_req = json.dumps(["MES_AUTH_RQT", ticket_to_second,encrypted_iv_tag_auth_data, hmac, encrypted_data,tag])
                    ccsock.sendall(mes_req)
                    ccsock.close()
                else:
                    print "Authentication Failed"`
                    return


            # QUERY packet
            if data[0] == "query":
                global CONNECTION_LIST
                CONNECTION_LIST = data[1]

            # ERROR packet
            if data[0] == "error":
                print("Duplicated username, try again.")
                DUPLICATE = 1
                return

            if data[0] == "AUTH_ERR":
                print "Authentication failed"
                return


        # except Exception as x:
        #     print "Something is wrong with the system, resuming..."

# INPUT : Message,Socket
# OUTPUT : None
# Method takes the inputs and sends to server after encrypting the message
def send_encrypted_message_to_server(message_type,message,s):
    data = json.dumps(message)
    encrypted_data,tag = encrypt_with_shared_key(session_key,iv,data,auth)
    #Encrypt using server's public key and sending them to the server.
    encrypted_tag_iv_auth = encryptTagIvAuth(tag,iv,auth,s_public_key)
    info = [message_type, encrypted_data, encrypted_tag_iv_auth, nonce]
    mes = json.dumps(info)
    s.sendall(mes)

#Fetches the user name using the ip address
def get_user_from_source(source):
    for client in CONNECTION_LIST:
        if(client[1] == source):
            return client[0]

def message_receiving(ccsock, source):
    # try:
    while True:
        data = ccsock.recv(1000000)
        # MESSAGE packet
        if len(data) != 0:
            data = json.loads(data)

            if data[0] == "MES_REQ":
                mes = json.dumps(["MES_REQ_RES",nonce])
                ccsock.sendall(mes)

            if data[0] == "MES_REQ_RES":
                nonce_b = data[1]
                second_client = get_user_from_source(source)
                if second_client is not None:
                    message = [args.user,source,nonce,nonce_b]
                    send_encrypted_message_to_server("TK_RQT",message, sock)
                else:
                    print "No such client exists"

            if data[0] == "MES_AUTH_RQT":
                ticket_to_second = data[1]
                encrypted_iv_tag_auth_data = data[2]
                hmac = data[3]
                encrypted_diffie = data[4]
                new_tag = data[5]


                decrypted_tag_iv_auth = decrypt_CTR_with_shared_key(session_key,encrypted_iv_tag_auth_data,nonce)

                if not verify_hmac_with_shared_key(session_key,decrypted_tag_iv_auth,hmac):
                    print "HMAC verification failed during Client Challenge Response"
                    return

                ticket_tag = decrypted_tag_iv_auth[0]
                new_iv = decrypted_tag_iv_auth[1]
                new_auth = decrypted_tag_iv_auth[2]
                decrypted_ticket = decrypt_with_shared_key(session_key,new_iv,ticket_tag,ticket_to_second,new_auth)

                requesting_client_uname = decrypted_ticket[0]
                shared_client_key = decrypted_ticket[1]
                second_client_nonce = decrypted_ticket[2]

                client_name_from_source = get_user_from_source(source)
                if nonce == second_client_nonce and client_name_from_source == requesting_client_uname :
                    decrypted_diffie = decrypt_with_shared_key(shared_client_key,new_iv,new_tag,encrypted_diffie,new_auth)
                    d2 = pyDH.DiffieHellman()
                    d2_pubkey = d2.gen_public_key()
                    dh_shared_key = d2.gen_shared_key(decrypted_diffie[0])
                    requesting_client_nonce = decrypted_diffie[1]
                    nonce_msg = json.dumps([requesting_client_nonce, nonce])
                    encrypted_nonce, nonce_tag = encrypt_with_shared_key(dh_shared_key, new_iv,nonce_msg, new_auth)
                    second_diffie = json.dumps([d2_pubkey])
                    encrypted_second_diffie, diffie_tag = encrypt_with_shared_key(shared_client_key, new_iv,second_diffie, new_auth)
                    info = ["MES_AUTH_RES",encrypted_nonce, nonce_tag, encrypted_second_diffie, diffie_tag]
                    mes = json.dumps([info])
                    ccsock.sendall(mes)
                else:
                    print "Authentication failed during Client Challenge Response"
                    return


            if data[0] == "MES_AUTH_RES":
                encrypted_nonce = data[1]
                nonce_tag = data[2]
                encrypted_second_diffie = data[3]
                diffie_tag = data[4]
                #TODO How to fetch the shared_client_key here, how to keep track of multiple conversations, hence multiple shared client keys
                decrypted_diffie = decrypt_with_shared_key(shared_client_key,iv,diffie_tag,encrypted_second_diffie,auth)
                decrypted_nonce_msg = decrypt_with_shared_key(decrypted_diffie[0],iv,nonce_tag,encrypted_nonce,auth)
                self_nonce = decrypted_nonce_msg[0]
                requesting_client_nonce = decrypted_nonce_msg[1]
                if self_nonce == nonce:
                    mes = json.dumps(["MES_AUTH_FIN",requesting_client_nonce])
                    ccsock.sendall(mes)
                else:
                    print "Authentcation failed during Client Challenge Response"
                    return

            if data[0] == "MES_AUTH_FIN" and data[1] == nonce:
                print "Authentication Successful" # TODO need to send the message from here.

            if data[0] == "message":
                 print ("\n" + "<-" + "<From " + source[0] + ":" + str(source[1]) + ":" + data[1] + ">: " + data[2])
    # except Exception as x:
    #     print "There is something wrong, resuming..."


if __name__ == "__main__":

    # addresses + usernames of logged in users
    CONNECTION_LIST = []

    # inform that the list is updated or not
    # FLAG_UPDATE = 0

    # inform if the username is already used by another
    DUPLICATE = 0

    # inform if the connection to the server is lost
    CONN_AVAI = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mes_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    parser = argparse.ArgumentParser()
    parser.add_argument("-sip", help="specify server ip to connect")
    parser.add_argument("-u", "--user", help="send the username")
    # parser.add_argument("-p", "--pass", help="send the password")
    parser.add_argument("-sp", "--port", type=int, default = 5550, help="specify port to connect")
    parser.add_argument("-sk",help = "Server Public Key")
    args = parser.parse_args()

    #Server Public Key
    s_public_key = ""

    #Global variables required for authentication
    iv = os.urandom(16)
    auth = os.urandom(16)
    nonce = os.urandom(16)
    d1 = pyDH.DiffieHellman()
    d1_pubkey = d1.gen_public_key()

    # try:
    if args.user and args.sip and args.port and args.sk:

        #loading server public key
        s_public_key = load_public_key(args.sk)

        tcp_port = random.randint(5000, 6000)
        info = ["signin", args.user, tcp_port]
        mes = json.dumps(info)

        sock.connect((args.sip, args.port))
        sock.sendall(mes)

        mes_sock.bind(('0.0.0.0', tcp_port))
        mes_sock.listen(5)

        thread_send = threading.Thread(target = send, args=(args.sip, args.port))
        thread_send.start()

        thread_receive = threading.Thread(target = receive, args=(args.sip, args.port))
        thread_receive.start()

        while True:
            csock, addr = mes_sock.accept()

            thread_message = threading.Thread(target = message_receiving, args =(csock, addr))
            thread_message.start()


        # if DUPLICATE == 0:
        #     while True:
        #         c2c_sock, source = mes_sock.accept()

        # mes_rev = threading.Thread(target = message_receiving)
        # mes_rev.start()

    # except Exception as x:
    #     print "Please provide all needed information!"



############## SWITCH TO SENDTO() WITH NO CONNECT METHOD!
