#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for reading and writing to files
with wrapping python methods.
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
import os


def reader(path):
    """ Read in all of a textual file """

    with open(path, 'r') as read:
        message = read.read()
    return message


def binary_reader(path):
    """ Read in all of a file in binaries """

    with open(path, 'rb') as read:
        message = read.read()
    return message


def writer(path, message):
    """ Write out text to a file """

    with open(path, 'w+') as write:
        write.write(message)


def binary_writer(path, message):
    """ Write out binaries to a file """

    with open(path, 'wb') as write:
        write.write(message)


def head_tail(path):
    head, tail = os.path.split(path)
    file = tail
    head = head
    return file, head
