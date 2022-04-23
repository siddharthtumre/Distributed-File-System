import socket
import base64
from enum import Enum
import sys
import time
import rsa

class Auth(Enum):
    NULL = 0
    AUTHORIZED = 1
    UNAUTHORIZED = 2

def main(port_number):
    ClientSocket = socket.socket()
    host = '127.0.0.1'
    port = port_number

    print('Waiting for connection')
    try:
        ClientSocket.connect((host, port))

        publicKey, privateKey = rsa.newkeys(512)

        public_key_sent_by_server = ClientSocket.recv(2048)
        public_key_sent_by_server = rsa.key.PublicKey.load_pkcs1(public_key_sent_by_server, format='DER')
        print(f"Public key: {public_key_sent_by_server}")

        ClientSocket.send(publicKey.save_pkcs1(format='DER'))

        username = input("Enter Username: ")
        ClientSocket.send(rsa.encrypt(username.encode(), public_key_sent_by_server))

        password = input("Enter password: ")
        # password = password.encode('utf-8')
        # encoded_password = base64.b64encode(password)
        ClientSocket.send(rsa.encrypt(password.encode(), public_key_sent_by_server))

        auth_status = Auth.NULL

        #Response after entering user credentials
        data = ClientSocket.recv(2048)
        data = rsa.decrypt(data, privateKey).decode()
        print(f"{data}")
        if data != "Incorrect Username or Password":
            auth_status = Auth.AUTHORIZED

        while auth_status == Auth.AUTHORIZED:

            # Info of operations that can be performed
            info = ClientSocket.recv(2048)
            info = info.decode('utf-8')
            print(f"{info}")

            choice = int(input("Enter Choice: "))
            ClientSocket.send(rsa.encrypt(str(choice).encode(), public_key_sent_by_server))

            status = ClientSocket.recv(2048)
            status = rsa.decrypt(status, privateKey).decode()
            print(status)
            if choice == 1:
                name_of_directory = input()
                ClientSocket.sendall(rsa.encrypt(name_of_directory.encode(), public_key_sent_by_server))
            elif choice == 2:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
            elif choice == 3:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
            elif choice == 4:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                time.sleep(1)
            elif choice == 5:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                time.sleep(1)
                data = input("Enter data to write to file: ")
                ClientSocket.sendall(rsa.encrypt(data.encode(), public_key_sent_by_server))
            elif choice == 6:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                data = input("Enter data to write to file: ")
                ClientSocket.sendall(rsa.encrypt(data.encode(), public_key_sent_by_server))
            elif choice == 7:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
            elif choice == 8:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                time.sleep(1)
                data = input("Enter size: ")
                ClientSocket.sendall(rsa.encrypt(data.encode(), public_key_sent_by_server))
            elif choice == 9:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                message = ClientSocket.recv(2048)
                message = message.decode("utf-8")
                print(message)
            elif choice == 10:
                name_of_file = input()
                ClientSocket.sendall(rsa.encrypt(name_of_file.encode(), public_key_sent_by_server))
                time.sleep(1)
                share_with_user = input("Enter the name of user to share with: ")
                ClientSocket.sendall(rsa.encrypt(share_with_user.encode(), public_key_sent_by_server))
                time.sleep(1)
                permissions = input("Select the file permissions: 1. Read, 2. Read and Write: ")
                ClientSocket.sendall(rsa.encrypt(permissions.encode(), public_key_sent_by_server))
            elif choice == 11:
                message = ClientSocket.recv(2048)
                message = message.decode("utf-8")
                print(message)
            elif choice == 0:
                message = ClientSocket.recv(2048)
                message = rsa.decrypt(message, privateKey).decode()
                print(message)
                ClientSocket.close()
                break
            elif status == "Invalid input":
                pass

            # After performing operation
            status = ClientSocket.recv(2048)
            status = rsa.decrypt(status, privateKey).decode()
            print(status)

    except socket.error as e:
        print(str(e))


    ClientSocket.close()

if __name__=="__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py port_number")
    else:
        port_number = int(sys.argv[1])
        mount = sys.argv[1]
        main(port_number)