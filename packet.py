# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from bitstring import pack, BitArray, BitStream
from crccheck.checksum import Checksum16
from log import *


class Packet:  # Creates Base Class that will hold all of the Packet Information in a Dict
    def __init__(self):
        self.header = {
            'srcport': 0,  # 16 Bits 0-16
            'dstport': 0,  # 16 Bits 16-32
            'seqnum': 0,  # 32 Bits 32-64
            'acknum': 0,  # 32 Bits 64-96
            'dataoffset': 5,  # 4 Bits 96-100
            'reserved': 0,  # 6 Bits 100-106

            # Flags Field
            'urg': 0,  # 1 Bits 106
            'ack': 0,  # 1 Bits 107
            'psh': 0,  # 1 Bits 108
            'rst': 0,  # 1 Bits 109
            'syn': 0,  # 1 Bits 110
            'fin': 0,  # 1 Bits 111

            'window': 0,  # 16 Bits 112-128
            'checksum': 0,  # 16 Bits 128-144
            'urgtptr': 0,  # 16 Bits 144-160
        }

        # Format used for BitArray
        self.bitfmt = "uint:16=srcport," \
                      "uint:16=dstport," \
                      "uint:32=seqnum," \
                      "uint:32=acknum," \
                      "uint:4=dataoffset," \
                      "uint:6=reserved," \
                      "uint:1=urg," \
                      "uint:1=ack," \
                      "uint:1=psh," \
                      "uint:1=rst," \
                      "uint:1=syn," \
                      "uint:1=fin," \
                      "uint:16=window," \
                      "uint:16=checksum," \
                      "uint:16=urgtptr," \
 \
            # Binary of total Header
        self.binary = None
        self.pbytes = None
        logger.info('Created Packet: %s', self)

    def encode(self):  # Inserts a Checksum and Encodes the Packet to be sent
        self.pbytes = pack(self.bitfmt, **self.header)  # Fake Packet for Checksum to be made
        self.binary = self.pbytes.bin
        self.header['checksum'] = self.calc_checksum()
        self.pbytes = pack(self.bitfmt, **self.header)  # Final Packet
        self.binary = self.pbytes.bin
        logger.info('Encoded Packet: %s Checksum: %s', self, self.header['checksum'])
        return self.pbytes.bytes

    def calc_checksum(self):  # Calculates Checksum, saves to Packet['checksum']
        self.header['checksum'] = Checksum16.calc(self.pbytes.bytes)
        logger.info('Inserted Checksum: %s', self)
        return self.header['checksum']

    def check_checksum(self):  # Takes Incoming Packet and Verifies Checksum is Correct
        incoming_checksum = self.header['checksum']
        self.header['checksum'] = 0
        self.pbytes = pack(self.bitfmt, **self.header)  # Fake Packet for Checksum to be made
        self.binary = self.pbytes.bin
        self.header['checksum'] = self.calc_checksum()
        if incoming_checksum == self.header['checksum']:
            return True  # If Checksum is Correct return True
        else:
            return False  # If Checksum is Incorrect return False

    def decode(self):  # Takes a Incoming Packet and Decodes Binary into data for Packer.header
        self.header['srcport'] = int(self.binary[0:16], 2)
        self.header['dstport'] = int(self.binary[16:32], 2)
        self.header['seqnum'] = int(self.binary[32:64], 2)
        self.header['acknum'] = int(self.binary[64:96], 2)
        self.header['dataoffset'] = int(self.binary[96:100], 2)
        self.header['reserved'] = int(self.binary[100:106], 2)
        self.header['urg'] = int(self.binary[106], 2)
        self.header['ack'] = int(self.binary[107], 2)
        self.header['psh'] = int(self.binary[108], 2)
        self.header['rst'] = int(self.binary[109], 2)
        self.header['syn'] = int(self.binary[110], 2)
        self.header['fin'] = int(self.binary[111], 2)
        self.header['window'] = int(self.binary[112:128], 2)
        self.header['checksum'] = int(self.binary[128:144], 2)
        self.header['urgtptr'] = int(self.binary[144:160], 2)
        logger.info('Decoded Packet: %s', self)
        return self


class DATA(Packet):  # Inherits from Packet Class, Adds Additional Data Field. Changes Checksum Routine
    def __init__(self):
        Packet.__init__(self)
        self.data = BitStream()
        logger.info('Created DATA Packet: %s', self)

    def encode(self):  # Inserts a Checksum and Encodes the Packet to be sent
        self.pbytes = pack(self.bitfmt, **self.header)  # Fake Packet for Checksum to be made
        self.pbytes.append(self.data)
        self.header['checksum'] = self.calc_checksum()
        self.pbytes = pack(self.bitfmt, **self.header)  # Final Packet with Checksum and Data
        self.pbytes.append(self.data)
        self.binary = self.pbytes.bin
        logger.info('Encode DATA Packet: %s Checksum: %s', self, self.header['checksum'])
        return self.pbytes.bytes

    def calc_checksum(self):  # Calculates Checksum, saves to Packet['checksum']
        self.header['checksum'] = Checksum16.calc(self.pbytes.bytes)
        logger.info('Inserted Checksum: %s', self)
        return self.header['checksum']


class ACK(Packet):  # Inherits from Packet, Sets Flag for ACK Type Packet
    def __init__(self):
        Packet.__init__(self)
        self.header['ack'] = 1
        logger.info('Created ACK Packet: %s', self)


class SYN(Packet):  # Inherits from Packet, Sets Flag for SYN Type Packet
    def __init__(self):
        Packet.__init__(self)
        self.header['syn'] = 1
        logger.info('Created SYN Packet: %s', self)


class SYNACK(Packet):  # Inherits from Packet, Sets Flag for SYNACK Type Packet
    def __init__(self):
        Packet.__init__(self)
        self.header['syn'] = 1
        self.header['ack'] = 1
        logger.info('Created SYN-ACK Packet: %s', self)


class FIN(Packet):  # Inherits from Packet, Sets Flag for FIN Type Packet
    def __init__(self):
        Packet.__init__(self)
        self.header['fin'] = 1
        logger.info('Created FIN Packet: %s', self)


class FINACK(Packet):  # Inherits from Packet, Sets Flag for FINACK Type Packet
    def __init__(self):
        Packet.__init__(self)
        self.header['fin'] = 1
        self.header['ack'] = 1
        logger.info('Created FIN-ACK Packet: %s', self)
