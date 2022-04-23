import socket
import re
import os
from _thread import *
from enum import Enum
import sys
import time
import rsa
from fs import Filesystem
import pyfuse3
import trio
import subprocess
import sqlite3
import glob
import base64
import cryptocode

publicKey, privateKey = rsa.newkeys(512)
key = "secret-key"

server_mount = "/home/siddharth/dfs/mountpoint"

class Auth(Enum):
    NULL = 0
    AUTHORIZED = 1
    UNAUTHORIZED = 2

def authenticate_user(username, password):
    connection = sqlite3.connect("sqlite3.db")
    cursor = connection.cursor()

    rows = cursor.execute("SELECT username, password from user WHERE username = ? AND password = ?", (username, str(password), )).fetchall()
    global auth_status
    auth_status = Auth.NULL
    
    if len(rows) == 1:
        auth_status = Auth.AUTHORIZED
        return auth_status
    else:
        auth_status = Auth.UNAUTHORIZED
        return auth_status

def create_directory(username, name_of_directory):
    user_dir_path = os.path.join(server_mount, username)
    # print(user_dir_path)

    if os.path.isdir(user_dir_path) == False:
        try:  
            os.mkdir(user_dir_path)
            print ("Successfully created the directory %s " % user_dir_path)	
        except OSError:
            print ("Creation of the directory failed")

    new_folder_path = os.path.join(user_dir_path, name_of_directory)
    if os.path.isdir(new_folder_path) == False:
        try:  
            os.mkdir(new_folder_path)
            print ("Successfully created the directory ")
            return "Successfully created the directory"	
        except OSError:
            print ("Creation of the directory failed")
            return("Creation of the directory failed")
    else:
        return "Directory already exists\n"

def remove_directory(username, name_of_directory):
    user_dir_path = os.path.join(server_mount, username)
    # print(user_dir_path)

    if os.path.isdir(user_dir_path) == False:
        try:  
            os.mkdir(user_dir_path)
            print ("Successfully created the directory %s " % user_dir_path)	
        except OSError:
            print ("Creation of the directory %s failed" % user_dir_path)

    new_folder_path = os.path.join(user_dir_path, name_of_directory)
    if os.path.isdir(new_folder_path) == False:
        return "Directory does not exists\n"
    else:
        try:
            os.rmdir(new_folder_path)
            print("Successfully deleted the directory %s" % new_folder_path)
            return "Successfully deleted the directory"
        except OSError:
            print ("Deletion of the directory %s failed" % new_folder_path)

def create_file(username, name_of_file):
    user_dir_path = os.path.join(server_mount, username)

    if os.path.isdir(user_dir_path) == False:
        try:  
            os.mkdir(user_dir_path)
            print ("Successfully created the directory %s " % user_dir_path)	
        except OSError:
            print ("Creation of the directory %s failed" % user_dir_path)
    
    new_file_path = os.path.join(user_dir_path, name_of_file)
    print(new_file_path)
    if os.path.isfile(new_file_path):
        return "File already exists"
    else:
        fp=open(new_file_path, 'w')
        fp.close()
        return "File successfully created"

def check_if_is_a_shared_file(name_of_file, username):
    files = list_all_files(username)
    # print("-----------")
    # print(files)
    for file in files:
        if name_of_file == file[0]:
            if len(name_of_file.split("/")) != 1:
                return True, os.path.join(server_mount, name_of_file), file[1]
            else: 
                return True, os.path.join(server_mount, username, name_of_file), file[1]
    return False, "", -1
        
    

def read_file(username, name_of_file):
    flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
    if not flag:
        return "File does not exist"
    if os.path.isfile(new_file_path):
        print(new_file_path)
        fp=open(new_file_path, 'r')
        data = fp.read()
        print(data)
        data = cryptocode.decrypt(data, key)
        # print(data)
        print(f"data: {data}")
        fp.close()
        return data
    else:
        return "File does not exist"

def write_file(username, name_of_file, data):
    user_dir_path = os.path.join(server_mount, username)

    if os.path.isdir(user_dir_path) == False:
        try:  
            os.mkdir(user_dir_path)
            print ("Successfully created the directory %s " % user_dir_path)	
        except OSError:
            print ("Creation of the directory %s failed" % user_dir_path)
    
    flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
    # print(permissions)
    # print("----------" + new_file_path)
    if not flag:
        return "File does not exist"
    if permissions == "Read and Write Access" or permissions == "owner":
        fp = open(new_file_path, 'w')
        data = cryptocode.encrypt(data, key)
        fp.write(data)
        fp.close()
        return "File write successful"
    else:
        return "You do not have permissions"

def append_file(username, name_of_file, data):
    user_dir_path = os.path.join(server_mount, username)

    if os.path.isdir(user_dir_path) == False:
        try:  
            os.mkdir(user_dir_path)
            print ("Successfully created the directory %s " % user_dir_path)	
        except OSError:
            print ("Creation of the directory %s failed" % user_dir_path)
    
    flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
    if permissions == "Read and Write Access"  or permissions == "owner":
        # print(data)
        existing_data = read_file(username, name_of_file)
        fp = open(new_file_path, 'w')
        data = cryptocode.encrypt(existing_data + data, key)
        # print(data)
        fp.write(data)
        fp.close()
        return "File write successful"
    else:
        return "You do not have permissions"

def delete_file(username, name_of_file):
    user_dir_path = os.path.join(server_mount, username)

    if os.path.isdir(user_dir_path) == False:
        return "File does not exist"
    else:
        flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
        print(new_file_path)
        if os.path.isfile(new_file_path):
            if permissions == "owner":
                os.remove(new_file_path)
                return "File deleted successfully"
            else:
                return "You don't have permission to delete"
        else:
            return "File does not exist"

def truncate_file(username, name_of_file, size):
    user_dir_path = os.path.join(server_mount, username)

    if os.path.isdir(user_dir_path) == False:
        return "File does not exist"
    else:
        flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
        print(new_file_path)
        if os.path.isfile(new_file_path):
            if permissions == "Read and Write Access"  or permissions == "owner":
                existing_data = read_file(username, name_of_file)
                data = existing_data[:size]

                write_file(username, name_of_file, data)
                return "File truncated successfully"
            else:
                return "You do not have permissions"
        else:
            return "File does not exist"

def access_modify_status(username, name_of_file):
    user_dir_path = os.path.join(server_mount, username)
    if os.path.isdir(user_dir_path) == False:
        return "File does not exist"
    else:
        flag, new_file_path, permissions = check_if_is_a_shared_file(name_of_file, username)
        if os.path.isfile(new_file_path):
            if permissions == "owner":
                status = subprocess.getoutput("stat "+new_file_path)
                return "\n".join(status.split("\n")[4:-1])
            else:
                return "Only owner of the file has access"
        else:
            return "File does not exist"

def share_file(username, name_of_file, shared_with, permissions):
    if permissions != 1 and permissions != 2:
        return "Invalid input for permissions"
    user_dir_path = os.path.join(server_mount, username)
    if os.path.isdir(user_dir_path) == False:
        return "File does not exist"
    else:
        new_file_path = os.path.join(user_dir_path, name_of_file)
        if not os.path.isfile(new_file_path):
            return "File does not exist"
        else:
            connection = sqlite3.connect("sqlite3.db")
            cursor = connection.cursor()

            rows = cursor.execute("SELECT username from user WHERE username = ?", (shared_with,))
            data = rows.fetchall()
            if len(data) == 0:
                return f"There is no one with username: {shared_with} in the system"
            else:
                check_if_already_shared = cursor.execute("SELECT filepath, permissions from shared WHERE shared_with = ? AND filepath =?", (shared_with, "/".join(new_file_path.split("/")[-2:]))).fetchall()
                if len(check_if_already_shared) != 0:
                    # print(check_if_already_shared)
                    for row in check_if_already_shared:
                        if permissions == 2 and 6>row[1]:
                            cursor.execute("UPDATE shared SET permissions=? WHERE shared_with = ? AND filepath = ?", (6, shared_with, "/".join(new_file_path.split("/")[-2:])))
                            connection.commit()
                            return "Permissions updated"
                        else:
                            return "Already shared"
                if permissions == 1:
                    cursor.execute("INSERT into shared VALUES(?, ?, 4)", ("/".join(new_file_path.split("/")[-2:]), shared_with, ))
                    connection.commit()
                    connection.close()
                    return "Shared successfully"
                elif permissions == 2:
                    cursor.execute("INSERT into shared VALUES(?, ?, 6)", ("/".join(new_file_path.split("/")[-2:]), shared_with, ))
                    connection.commit()
                    connection.close()
                    return "Shared successfully"
           
def list_all_files(username):
    connection = sqlite3.connect("sqlite3.db")
    cursor = connection.cursor()
    rows = cursor.execute("SELECT filepath, permissions from shared WHERE shared_with=?", (username,)).fetchall()
    allFiles = []
    for row in rows:
        if row[1] == 4:
            allFiles.append((row[0], "Read Access"))
        if row[1] == 6:
            allFiles.append((row[0], "Read and Write Access"))

    user_dir_path = os.path.join(server_mount, username)
    for root, directories, files in os.walk(user_dir_path):
        for directory in directories:
            allFiles.append((os.path.join(directory) + "/", "owner"))
        for filename in files:  
            allFiles.append(("/".join(os.path.join(root, filename).split("/")[6:]), "owner"))
    return allFiles

def threaded_client(connection):
    connection.send(publicKey.save_pkcs1(format='DER'))

    public_key_sent_by_client = connection.recv(2048)
    public_key_sent_by_client = rsa.key.PublicKey.load_pkcs1(public_key_sent_by_client, format='DER')

    print(f"Public key: {public_key_sent_by_client}")

    username = connection.recv(2048)
    username = rsa.decrypt(username, privateKey).decode()
    print(f"Received Username {username}")

    password = connection.recv(2048)
    password = rsa.decrypt(password, privateKey).decode()
    password = base64.b64encode(password.encode('utf-8'))
    print(f"Received password {password}")

    authenticate_user(username, password)

    if auth_status == Auth.UNAUTHORIZED:
        connection.send(rsa.encrypt("Incorrect Username or Password".encode(), public_key_sent_by_client))
    else:
        connection.send(rsa.encrypt("You are authenticated\n".encode(), public_key_sent_by_client))
        time.sleep(1)

    while auth_status == Auth.AUTHORIZED:
        connection.send("Here are some operations you can perform\n1. Create a directory\n2. Remove a directory\n3. Create a file\n4. Read a file\n5. Write to a file\n6. Append to a file\n7. Delete a file\n8. Truncate a file\n9. Access, modify & status change updates\n10. share a file\n11. List all files\n0. Exit".encode('utf-8'))
        time.sleep(1)
        status = connection.recv(2048)
        status = int(rsa.decrypt(status, privateKey).decode())

        if status == 1:
            connection.send(rsa.encrypt("Enter the name of the directory: ".encode(), public_key_sent_by_client))
            name_of_directory = connection.recv(2048)
            name_of_directory = rsa.decrypt(name_of_directory, privateKey).decode()
            output = create_directory(username, name_of_directory)


            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 2:
            connection.send(rsa.encrypt("Enter the name of the directory: ".encode(), public_key_sent_by_client))
            name_of_directory = connection.recv(2048)
            name_of_directory = rsa.decrypt(name_of_directory, privateKey).decode()
            output = remove_directory(username, name_of_directory)


            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 3:
            connection.send(rsa.encrypt("Enter the name of the file to create: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            output = create_file(username, name_of_file)
            print(output)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 4:
            connection.send(rsa.encrypt("Enter the name of the file to read: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            print(name_of_file)
            output = read_file(username, name_of_file)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 5:
            connection.send(rsa.encrypt("Enter the name of the file to write: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            print(name_of_file)
            data = connection.recv(2048)
            data = rsa.decrypt(data, privateKey).decode()
            output = write_file(username, name_of_file, data)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 6:
            connection.send(rsa.encrypt("Enter the name of the file to append: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            print(name_of_file)
            data = connection.recv(2048)
            data = rsa.decrypt(data, privateKey).decode()
            output = append_file(username, name_of_file, data)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 7:
            connection.send(rsa.encrypt("Enter the name of the file to delete: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            print(name_of_file)
            output = delete_file(username, name_of_file)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 8:
            connection.send(rsa.encrypt("Enter the name of the file to truncate: ".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()

            print(name_of_file)
            size = connection.recv(2048)
            size = int(rsa.decrypt(size, privateKey).decode())
            output = truncate_file(username, name_of_file, size)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)
        elif status==9:
            connection.send(rsa.encrypt("Enter the name of the file".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()
            output = access_modify_status(username, name_of_file)
            connection.send(output.encode("utf-8"))
            time.sleep(1)
            
            connection.send(rsa.encrypt("\n\n".encode(), public_key_sent_by_client))
            time.sleep(1)
        
        elif status==10:
            connection.send(rsa.encrypt("Enter the name of the file".encode(), public_key_sent_by_client))
            name_of_file = connection.recv(2048)
            name_of_file = rsa.decrypt(name_of_file, privateKey).decode()

            shared_with = connection.recv(2048)
            shared_with = rsa.decrypt(shared_with, privateKey).decode()

            permissions = connection.recv(2048)
            permissions = int(rsa.decrypt(permissions, privateKey).decode())
            
            output = share_file(username, name_of_file, shared_with, permissions)

            connection.send(rsa.encrypt(output.encode(), public_key_sent_by_client))
            time.sleep(1)

        elif status == 11:
            connection.send(rsa.encrypt("Listing all files".encode(), public_key_sent_by_client))
            output = list_all_files(username)
            print(output)

            message = ""
            for i in output:
                message += i[0] + " - " + i[1] + "\n"
            

            connection.send(message.encode("utf-8"))
            time.sleep(1)
            connection.send(rsa.encrypt("\n\n".encode(), public_key_sent_by_client))
            time.sleep(1)


        elif status == 0:
            connection.send(rsa.encrypt("Exiting".encode(), public_key_sent_by_client))
            time.sleep(1)
            connection.send(rsa.encrypt("Successfully exited".encode(), public_key_sent_by_client))
            connection.close()
            break
        else:
            connection.send(rsa.encrypt("Invalid input".encode(), public_key_sent_by_client))
            time.sleep(1)
            connection.send(rsa.encrypt("Please select from available options".encode(), public_key_sent_by_client))
            time.sleep(1)   
    
def main(port_number):
    ServerSocket = socket.socket()
    host = '127.0.0.1'
    port = port_number
    ThreadCount = 0
    try:
        ServerSocket.bind((host, port))
    except socket.error as e:
        print(str(e))
    
    print('Waiting for a Connection..')
    ServerSocket.listen(5)

    while True:
        Client, address = ServerSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(threaded_client, (Client, ))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSocket.close()

if __name__=="__main__":
    if len(sys.argv) < 2:
        print("Usage: python server.py port_number")
    else:
        port_number = int(sys.argv[1])
        # start_new_thread(os.system, ("python fs.py source mountpoint", ))
        main(port_number)