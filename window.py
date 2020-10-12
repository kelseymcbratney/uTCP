# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from packet import *
from log import *
import time


class PacketWrapper:
    def __init__(self, packet):
        self.packet = self.packet
        self.isacked = False
        self.timestamp = time.time()
        self.seqnum = packet.header['seqnum']
        self.sizeofdata = len(packet.data)


class Window:
    def __init__(self, window):
        self.windowSize = window
        self.list = []

    def add_to_window(self, packet):  # Adds Packet to Window
        logger.info("Adding Element to Window: %s", self)
        insert = PacketWrapper(packet)
        self.list.append(insert)

    def check_window(self):  # Traverses Window and Finds Unacked Packets
        unacklist = []
        for i in self.list:
            if self.list[i].isacked is False:
                unacklist.append(self.list[i])
        return unacklist

    def slide(self):  # Deletes first Packet that has been inserted, allowing more packets to be added
        del self.list[0]

    def ack_window(self, ack):  # Searches List for Packet and marks as ACK
        for i in self.list:
            if i.seqnum == ack:
                i.isacked = True



