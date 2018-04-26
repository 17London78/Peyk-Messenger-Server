#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for Handling authenticated encryption
with RSA-AES method using Crypto library
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
from Crypto.Random import random
from Files.Ciphers import RSA, AES


class Cipher:
    """A base class for authenticated encryption and decryption"""

    def __init__(self, data=None, priv_key=None, priv_key_password=None,
                 recipient_pubkey=None):
        if type(data) == tuple:
            self.dataTuple = data
        elif type(data) == str:
            self.data = data
        self.privKey = priv_key
        self.privKeyPassword = priv_key_password
        self.r_pubkey_binary = recipient_pubkey

    @staticmethod
    def _lettergen():
        """ A random password generator for AES encrypting """

        letters = '!$%&0123456789<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZmnopqrstuvwxyz'
        letters = list(letters)
        # Using Crypto.Random library for cryptographic random function
        random.shuffle(letters)
        letters = ''.join(letters)
        return letters

    @staticmethod
    def _rsa_enc_cycle(plain_tuple, public_key):
        """ Encrypts all items in a tuple via RSA method """

        rsa = RSA.Encryptor()
        cipher_list = list()
        for i in range(0, len(plain_tuple)):
            cipher_list[i] = rsa.encrypt([i], public_key, 'b')
        return tuple(cipher_list)

    def _rsa_dec_cycle(self, cipher_tuple):
        """ Decrypts all items in a tuple via RSA method """

        rsa = RSA.Decryptor()
        plain_list = list()
        for i in range(0, len(cipher_tuple)):
            plain_list[i] = rsa.decrypt(
                cipher_tuple[i], self.privKey, self.privKeyPassword, 'b')
        return tuple(plain_list)


class Send(Cipher):
    """ Send class for authenticated encryption """

    def encrypt(self):
        data = self. data.encode('utf-8')
        aes = AES.aes()
        key = self._lettergen()
        aes_tuple = aes.enc(data, key)
        confidential = (aes_tuple[1], aes_tuple[2], aes_tuple[3])
        cipher_keys = self._rsa_enc_cycle(confidential, self.r_pubkey_binary)
        # ((aes.key, aes.nonce, aes.tag), message)
        message = (cipher_keys, aes_tuple[0])
        return message


class Receive(Cipher):
    """ Receive class for authenticated decryption """

    def decrypt(self):
        aes = AES.AES()
        confidential = self._rsa_dec_cycle(self.dataTuple[0])
        data = aes.dec(self.dataTuple[1], confidential[1], confidential[2],
                       confidential[0])
        if data is False:
            raise MessageTagDoesNotMatch
        return data.decode('utf-8')


class MessageTagDoesNotMatch(Exception):
    pass
