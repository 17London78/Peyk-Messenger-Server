#!/usr/bin/python3
"""
Peyk Secure Encrypted Messenger Server
GNU AGPL 3.0 Licensed
Copyright (C) 2018 17London78 Inc.
=========================================
A text template for using in other modules
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

instructions = """Instructions:
[<list>] to list all rooms

[<join>] [room_name] [room_password] to join/create/switch to a room, leave
password empty if it's a public room. ([] signs are not necessary)

[<manual>] to show instructions

[<quit>] to quit

Otherwise start typing and enjoy!
"""
listRoom1 = """Oops, no active rooms currently. Create your own!
Use [<join> room_name room_password] to create a room.
"""
listRoom2 = """Listing current rooms...
"""
noRoom = """You are currently not in any room!
Use [<list>] to see available rooms!
Use [<join> room_name room_password] to join a room! leave password empty if
it's a public room."""
