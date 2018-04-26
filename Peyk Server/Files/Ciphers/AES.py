#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for AES encrypt/decrypt using Crypto library
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
from Crypto.Cipher import AES as _AES
from Crypto.Hash import SHA3_256


class AES:
    """ Encrypt/decrypt via AES-EAX-256bit_key method """

    def enc(self, data, key):
        key_256bit = self._keygen(key)
        cipher = _AES.new(key_256bit, _AES.MODE_EAX)
        cipher_nonce = cipher.nonce
        cipher_data, cipher_tag = cipher.encrypt_and_digest(data)
        return cipher_data, key_256bit.encode('utf_8'), cipher_nonce, cipher_tag

    def dec(self, data, nonce, tag, key):
        key = self._keygen(key)
        decipher = _AES.new(key, _AES.MODE_EAX, nonce=nonce)
        plain_data = decipher.decrypt(data)
        try:
            decipher.verify(tag)
        except ValueError:
            plain_data = False
        return plain_data

    @staticmethod
    def _keygen(key):
        if type(key) is str:
            key = key.encode('utf-8')
        key_256bit = SHA3_256.new()
        key_256bit.update(key)
        key = key_256bit.digest()
        return key
