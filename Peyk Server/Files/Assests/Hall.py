#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for managing message I/O stream and rooms
=========================================
"""
__author__ = "Mohammad Mahdi Baghbani Pourvahid"
__copyright__ = "Copyright (C) 2018 17London78 Inc."
__credits__ = ["Jadi mirmirani, Xysun, Al Sweigart"]
__license__ = "AGPL 3.0"
__maintainer__ = "Mohammad Mahdi Baghbani Pourvahid"
__email__ = "Mohammad Mahdi Baghbani Pourvahid"
__version__ = "0.01-alpha"
__status__ = "Development"


import pickle
import os
from Crypto.Hash import SHA3_512
from Files.Ciphers import CipherManager
from Files.Assests import Texts


class Hall:
    """ Creating a hall with several public/private rooms """

    def __init__(self, server_name, path, priv_key, priv_key_password):
        self.servername = server_name
        self.path = path
        self.rooms = self._load_database()  # {roomName: Room}
        self.room_client_map = {}  # {clientName: roomName}
        self.instructions = Texts.instructions
        self.privKey = priv_key
        self.privKeyPassword = priv_key_password
        self.server_tag = '<$SERVER$>'

    def _room_load(self):
        """ Read in previously created rooms database """

        with open(self.path, 'rb') as handle:
            rooms = pickle.loads(handle.read())
        return rooms

    def _load_database(self):
        """ Loads previously created rooms if exists """

        rooms = {}
        if os.path.isfile(self.path):  # If database file exists then load it
            rooms = self._room_load()
        return rooms

    def _save_r_to_database(self):
        """ Saves newly created rooms to database """

        with open(self.path, 'wb+') as handle:
            pickle.dump(self.rooms, handle, pickle.HIGHEST_PROTOCOL)

    def welcome_new(self, new_client):
        """ Sending welcome message with
        instructions to newly connected client """

        msg = 'Welcome to {}!, enjoy your time.\n{}'.format(
            self.servername, self.instructions)
        send_tuple = (self.server_tag, msg)
        new_client.socket.sendall(pickle.dumps(send_tuple))

    def handle_msg(self, client, msg):
        """ Handling messages I/O stream and managing creating of rooms"""

        # Message is an order to server
        if msg[0] is self.server_tag:
            cipher = CipherManager.Receive(
                msg[1], self.privKey, self.privKeyPassword)
            # Decrypting message with server's private key
            msg = cipher.decrypt()
            # Join command for creating a room or switching to another room
            if "<join>" in msg:
                same_room = False
                msg_parts = msg.split()
                if len(msg_parts) >= 2:  # Error check
                    room_name = msg.split()[1]
                    room_password = None
                    if len(msg_parts) is 3:
                        room_password = msg_parts[2]

                    if client.name in self.room_client_map:  # Switching?
                        condition = self.room_client_map[client.user.username]
                        if condition == room_name:
                            msg = 'You are already in room: {}'.format(
                                room_name)
                            alert = (self.server_tag, msg)
                            client.socket.sendall(pickle.dumps(alert))
                            same_room = True
                        else:  # Switch
                            old_room = condition
                            self.rooms[old_room].remove_client(client)
                    if not same_room:
                        if room_name not in self.rooms:  # new room:
                            new_room = Room(room_name, room_password)
                            self.rooms[room_name] = new_room
                            self._save_r_to_database()
                        if self.rooms[room_name].tag is 'public':
                            self._add_to_room(room_name, client)
                        else:
                            if self.rooms[room_name].check_password(room_password):
                                self._add_to_room(room_name, client)
                            else:
                                msg = 'incorrect password! try again.'
                                alert = (self.server_tag, msg)
                                client.socket.sendall(pickle.dumps(alert))
                else:
                    message = (self.server_tag, self.instructions)
                    client.socket.sendall(pickle.dumps(message))
            # Command to show all available rooms and it's member count
            elif "<list>" in msg:
                self._list_rooms(client)
            # Command to show instructions again
            elif "<manual>" in msg:
                message = (self.server_tag, self.instructions)
                client.socket.sendall(pickle.dumps(message))
            # Command to exit [STILL UNDER DEVELOPMENT]
            elif "<quit>" in msg:  # TODO
                QUIT_STRING = '<$QUIT$>'
                client.socket.sendall(pickle.dumps(QUIT_STRING))
                self._remove_client(client)
        # Message to other clients
        else:
            # Check if in a room or not first
            if client.user.username in self.room_client_map:
                self.rooms[self.room_client_map[client.user.username]
                           ].broadcast(client, msg)
            else:
                msg = Texts.noRoom
                alert = (self.server_tag, msg)
                client.socket.sendall(pickle.dumps(alert))

    def _list_rooms(self, client):
        """ Show all available rooms and it's member count"""

        # Check if there are any rooms or not
        if len(self.rooms) == 0:
            msg = Texts.listRoom1
            message = (self.server_tag, msg)
            client.socket.sendall(pickle.dumps(message))

        else:
            # Building a list fom template and server's information
            msg = Texts.listRoom2
            for room in self.rooms:
                number = str(len(self.rooms[room].members))
                tag = self.rooms[room].tag
                msg += "{} <{}>: {} member(s)\n".format(room, tag, number)
            message = (self.server_tag, msg)
            client.socket.sendall(pickle.dumps(message))

    def _add_to_room(self, room_name, client):
        """ Handling adding a client to a room """

        self.rooms[room_name].add_member(client)
        self.room_client_map[client.user.username] = room_name

    def _remove_client(self, client):
        """ Handling removing a client to a room """

        if client.user.username in self.room_client_map:
            self.rooms[self.room_client_map[client.user.username]
                       ].remove_member(client)
            del self.room_client_map[client.user.username]


class Room:
    """ Room class for representing chat group """

    def __init__(self, name, password):
        self.name = name
        self.members = []  # a list of sockets
        self.members_pub_key = {}
        self.server_tag = '<$SERVER$>'
        self.new_client_tag = '<$NewKey$>'
        self.new_dict_tag = '<$NewDict$>'
        if password is None:
            self.tag = 'public'
        else:
            self.tag = 'private'
            self.password = self._encrypt_pw(password)

    def add_member(self, client):
        """ Adding new members to room and handling public key exchanges """

        self.members.append(client)
        self.members_pub_key[client.user.username] = client.user.pubKey
        self._client_key_broadcast(client)
        self._welcome_new(client)

    def _client_key_broadcast(self, client):
        """ Sends newly added client's public key to all room members"""

        name = client.user.username
        pub_key = client.user.pubKey
        key = (self.server_tag, self.new_client_tag, name, pub_key)
        key = pickle.dumps(key)
        for member in self.members:
            if member is not client:
                member.socket.sendall(key)

    def _welcome_new(self, client):
        """ Sends all room members public keys to newly added client
        and sends announcement to notify members of new member"""

        key_dict = self.members_pub_key.copy()
        message = (self.server_tag, self.new_dict_tag, key_dict)
        client.socket.sendall(pickle.dumps(message))
        announce = '{} joins {} !'.format(client.user.username, self.name)
        announce = (self.server_tag, announce)
        announce = pickle.dumps(announce)
        for member in self.members:
            if member is not client:
                member.socket.sendall(announce)

    def broadcast(self,  msg):
        """ Broadcasts messages to all members """

        msg = pickle.dumps(msg)
        for member in self.members:
            member.socket.sendall(msg)

    def remove_member(self, client):
        """ remove a member from room and send new public key dictionary
        to remaining members """

        self.members.remove(client)
        del self.members_pub_key[client.user.username]
        key = (self.server_tag, self.new_dict_tag, self.members_pub_key)
        self.broadcast(key)
        name = client.user.username
        leave_msg = '{} has left the room\n'.format(name)
        message = (self.server_tag, leave_msg)
        self.broadcast(message)

    def _encrypt_pw(self, password):
        """ Encrypts room's password  """

        hash_string = (self.name + password)
        hash_string = hash_string.encode('utf8')
        return SHA3_512.new(hash_string).hexdigest()

    def check_password(self, password):
        """ Validates entered password with room's password"""

        encrypted = self._encrypt_pw(password)
        return encrypted == self.password
