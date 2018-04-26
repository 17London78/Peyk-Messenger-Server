#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A module for reading and writing to files
with wrapping python methods.
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
