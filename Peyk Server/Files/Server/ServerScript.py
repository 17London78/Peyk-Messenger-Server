#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
Server module for encrypted group chat in Peyk
=========================================
Islamic Republic of Iran Broadcasting University (IRIBU)
Faculty of Telecommunication Engineering
Author: Mohammad Mahdi Baghbani Pourvahid
Major: Telecommunication Engineering
<MahdiBaghbani@protonmail.com>
https://www.MahdiBaghbanii.wordpress.com
https://www.GitHub.com/MahdiBaghbani
Company: 17London78 Inc.
https://www.17London78.ir
https://www.GitHub.com/17London78
=========================================
"""
import socket
import select
import pickle
from Files.Assests import Auth
from Files.Assests import Hall
from Files.Ciphers import CipherManager
from Files.Assests import BasicFunctions


class Client:
    """ Class for containing user and it's associated socket"""

    def __init__(self, sock, user):
        sock.setblocking(0)
        self.socket = sock
        self.user = user

    def fileno(self):
        return self.socket.fileno()


class Server:
    """ Main class for initialising a server """

    def __init__(self, server_name, pub_key_path, priv_key_path,
                 priv_key_password, tcp_ip, tcp_port, buffer_size, cas_path,
                 hall_path, password=None):
        self.servername = server_name
        self.ip = tcp_ip
        if type(tcp_port) is str:
            tcp_port = int(tcp_port)
        self.port = tcp_port
        if password is not None:
            self.password = password
        self.buffer = buffer_size
        self.publicKey = BasicFunctions.binaryReader(pub_key_path)
        self.privKey = BasicFunctions.binaryReader(priv_key_path)
        self.privKeyPassword = priv_key_password
        self.connection_list = []
        self.CAS = Auth.Authenticator(cas_path)
        self.Hall = Hall.Hall(self.servername, hall_path, self.privKey,
                              self.privKeyPassword)

    def _validator(self, sock):
        """ STILL UNDER DEVELOPMENT"""

        data = sock.recv(self.buffer)
        if data:
            data = pickle.loads(data)
            if self.password == data:
                state = 1
                sock.sendall(pickle.dumps(state))
                return state
            else:
                state = 0
                sock.sendall(pickle.dumps(state))
                return state
        else:
            return 0

    def start(self):
        """ The main function that starts server sockets and manages I/O """

        # Creating server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.ip, self.port))
        server_socket.listen(128)
        self.connection_list.append(server_socket)
        while True:
            read, write, error = select.select(self.connection_list, [], [])
            for sock in read:
                #  New connection
                if sock is server_socket:
                    client_raw, address = server_socket.accept()
                    # If server is private and has a password
                    if self.password is not None:
                        state = self._validator(client_raw)
                        # Correct password
                        if state is 1:
                            self._adding_to_hall(client_raw)
                        # Wrong password
                        else:
                            client_raw.close()
                    # If server is public
                    else:
                        self._adding_to_hall(client_raw)
                # New message
                else:
                    data = sock.socket.recv(self.buffer)
                    if data:
                        raw_tuple = pickle.loads(data)
                        self.Hall.handle_msg(sock, raw_tuple)
                    else:
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.socket.close()
                        self.connection_list.remove(sock)
            # Close error sockets
            for sock in error:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                self.connection_list.remove(sock)

    def _adding_to_hall(self, client_raw):
        """ Assigning a connection to hall process """

        client = self._client_connected(client_raw)
        if client is not 0:  # Successful
            # Registering new client to Hall
            self.connection_list.append(client)
            self.Hall.welcome_new(client)
        else:  # Connection lost
            client_raw.shutdown(socket.SHUT_RDWR)
            client_raw.close()

    def _client_connected(self, sock):
        """ Handling signup/login"""

        data = sock.recv(self.buffer)
        if data:
            data = pickle.loads(data)
            if data is 0:
                sock.sendall(pickle.dumps(self.publicKey))
                client = self._signup(sock)
                return client
            else:
                client = self._login(sock)
                return client
        else:
            return 0

    def _decrypt(self, cipher_data):
        """ Decrypting messages from clients """

        plain_list = list()
        for i in range(0, len(cipher_data)):
            cipher = CipherManager.Receive(cipher_data[i], self.privKey,
                                           self.privKeyPassword)
            plain_list[i] = cipher.decrypt()

        return tuple(plain_list)

    def _signup(self, sock):
        """ Signup process """

        data = sock.recv(self.buffer)
        if data:
            cipher_data = pickle.loads(data)
            username, password, pubkey = self._decrypt(cipher_data)
            try:
                self.CAS.add_user(username, password, pubkey)
                sock.sendall(pickle.dumps(0))
                return self._login(sock)
            except Auth.UsernameAlreadyExists:
                sock.sendall(pickle.dumps(1))
                self._signup(sock)
            except Auth.PasswordTooShort:
                sock.sendall(pickle.dumps(2))
                self._signup(sock)
        else:
            return 0

    def _login(self, sock):
        """ Login process """

        data = sock.recv(self.buffer)
        if data:
            cipher_data = pickle.loads(data)
            username, password = self._decrypt(cipher_data)
            try:
                self.CAS.login(username, password)
                sock.sendall(pickle.dumps(0))
                user = self.CAS.users[username]
                client = Client(sock, user)
                return client
            except Auth.InvalidUsername or Auth.InvalidPassword:
                sock.send(pickle.dumps(1))
                self._login(sock)
            except Auth.UserAlreadySignedIn:
                sock.send(pickle.dumps(2))
                self._login(sock)
        else:
            return 0
