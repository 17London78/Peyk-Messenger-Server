#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for organizing users of the server
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

import os
import pickle
from Crypto.Hash import SHA3_512


class Authenticator:
    """ Authenticator class manages registering users and their data """

    def __init__(self, path):
        self.path = path
        self.users = self._load_database()

    def _user_load(self):
        """ Read in previously registered user database """

        with open(self.path, 'rb') as handle:
            users = pickle.loads(handle.read())
        return users

    def _user_init(self):
        """ Setting all user login states to False"""

        users = self._user_load()
        for username in users:
            user = users[username]
            user.is_logged_in = False
        return users

    def _load_database(self):
        """ Loads previously registered users if exists """

        users = {}
        if os.path.isfile(self.path):
            users = self._user_init()
        return users

    def _save_u_to_database(self):
        """ Saves newly registered users to database """

        with open(self.path, 'wb+') as handle:
            pickle.dump(self.users, handle, pickle.HIGHEST_PROTOCOL)

    def add_user(self, username, password, pub_key):
        """ Add new user """

        if username in self.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        user_object = User(username, password, pub_key)
        self.users[username] = user_object
        self._save_u_to_database()

    def change_password(self, username, new_password, old_password=None):
        """ Change existing user password """

        if username in self.users:
            user = self.users[username]
            user.change_password(old_password, new_password)
            self._save_u_to_database()
        else:
            raise UsernameDoesNotExists(username)

    def login(self, username, password):
        """ Login a user inside """

        try:
            user = self.users[username]
        except KeyError:
            raise InvalidUsername(username)
        if user.is_logged_in is False:
            if not user.check_password(password):
                raise InvalidPassword(username, user)

            user.is_logged_in = True
            return True
        else:
            raise UserAlreadySignedIn(username)

    def is_logged_in(self, username):
        """ Checking user login state [True/False] """

        if username in self.users:
            return self.users[username].is_logged_in
        return False


class User:
    """ User class for containing a user information """

    def __init__(self, username, password, pub_key):
        self.username = username
        self.pubKey = pub_key
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False

    def _encrypt_pw(self, password):
        """ Hashes user password with SHA-3 512bit
        for storing in database """

        hash_string = (self.username + password)
        hash_string = hash_string.encode('utf8')
        return SHA3_512.new(hash_string).hexdigest()

    def check_password(self, password):
        """ Validating entered password with user's password """

        encrypted = self._encrypt_pw(password)
        return encrypted == self.password

    def change_password(self, old_password, new_password):
        """ Changes user's password """

        if self.is_logged_in is True:
            if self.check_password(old_password) is True:
                self.password = self._encrypt_pw(new_password)
            else:
                raise InvalidPassword(self.username)
        else:
            raise NotLoggedInError(self.username)


class AuthException(Exception):
    """ Parent class for exceptions """

    def __init__(self, username, user=None):
        super().__init__(username, user)
        self.username = username
        self.user = user


class UsernameDoesNotExists(AuthException):
    pass


class UsernameAlreadyExists(AuthException):
    pass


class UserAlreadySignedIn(AuthException):
    pass


class ClientDoesNotExist(AuthException):
    pass


class ClientAlreadyHasPublicKey(AuthException):
    pass


class PasswordTooShort(AuthException):
    pass


class InvalidUsername(AuthException):
    pass


class InvalidPassword(AuthException):
    pass


class NotLoggedInError(AuthException):
    pass


class PathDoesNotExist(AuthException):
    pass


class NotPermittedError(AuthException):
    pass
