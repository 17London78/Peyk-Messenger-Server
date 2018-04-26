#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for creating RSA private-public key set
& encrypt/decrypt RSA ciphers & digital sign/verify
functions using Crypto library
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

from Crypto.PublicKey import RSA as _RSA
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA3_512
from Files.Assests import BasicFunctions


class RSA:
    """ Creates a set of private and public keys """

    def __init__(self):
        self.private, self.public = self._generator()

    @staticmethod
    def _generator():
        """ Generates a random set of keys """

        private_set = _RSA.generate(2048)
        public_key = private_set.publickey()
        return private_set, public_key

    def export(self, pub_path, priv_path, password=0000):
        """ Writes private and public keys to PEM(.pem) file"""

        priv = self.private.exportKey('PEM', password)
        pub = self.public.exportKey('PEM')
        BasicFunctions.binary_writer(priv_path, priv)
        BasicFunctions.binary_writer(pub_path, pub)


class Encryptor:
    """ Encrypting a message with recipient public key """

    @staticmethod
    def encrypt(message, pub_key, mode):
        def encrypt(public_key):
            cipher = PKCS1_OAEP.new(public_key)
            cipher_text = cipher.encrypt(message)
            return cipher_text
        if mode is 'f':
            key = _RSA.importKey(BasicFunctions.binary_reader(pub_key))
            return encrypt(key)
        elif mode is 'b':
            key = _RSA.importKey(pub_key)
            return encrypt(key)


class Decryptor:
    """ Decrypting a message with receiver private key """

    @staticmethod
    def decrypt(message, priv_key, paswd, mode):
        def decrypt(private_key):
            cipher = PKCS1_OAEP.new(private_key)
            plaintext = cipher.decrypt(message)
            return plaintext
        if mode is 'f':
            key = _RSA.importKey(BasicFunctions.binary_reader(priv_key, paswd))
            return decrypt(key)
        elif mode is 'b':
            key = _RSA.importKey(priv_key, paswd)
            return decrypt(key)


class Signature:
    """ Digital signing and verifying signatures class """

    @staticmethod
    def sign(message, priv_key, paswd, mode):
        """ Signs a message with private key"""

        def sign(private_key):
            hash512 = SHA3_512.new(message)
            signature = pss.new(private_key).sign(hash512)
            return signature
        if type(message) is str:
            message = message.encode('utf-8')
        if mode is 'f':
            key = _RSA.importKey(BasicFunctions.binary_reader(priv_key), paswd)
            return sign(key)
        elif mode is 'b':
            key = _RSA.importKey(priv_key, paswd)
            return sign(key)

    @staticmethod
    def verify(message, pub_key, signature, mode):
        """ Verifies the authenticity of Digital signature"""

        def verify(public_key):
            hash512 = SHA3_512.new(message)
            verifier = pss.new(public_key)
            try:
                verifier.verify(hash512, signature)
            except (ValueError, TypeError):
                return False
            return True
        if type(message) is str:
            message = message.encode('utf-8')
        if mode is 'f':
            key = _RSA.importKey(BasicFunctions.binary_reader(pub_key))
            return verify(key)
        elif mode is 'b':
            key = _RSA.importKey(pub_key)
            return verify(key)
