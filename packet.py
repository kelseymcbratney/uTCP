# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from bitstring import pack, BitArray, BitStream
from crccheck.checksum import Checksum16
from log import *

class Packet:
    def __init__(self):
        self.header = {
            'srcport': 0,  # 16 Bits 0-16
            'dstport': 0,  # 16 Bits 16-32
            'seqnum': 0,  # 32 Bits 32-64
            'acknum': 0,  # 32 Bits 64-96
            'dataoffset': 0,  # 4 Bits 96-100
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

    def encode(self):
        self.pbytes = pack(self.bitfmt, **self.header)  # Fake Packet for Checksum to be made
        self.binary = self.pbytes.bin
        self.header['checksum'] = self.calc_checksum()
        self.pbytes = pack(self.bitfmt, **self.header)  # Final Packet
        self.binary = self.pbytes.bin
        logger.info('Encoded Packet: %s Checksum: %s', self, self.header['checksum'])
        return self

    def calc_checksum(self):
        self.header['checksum'] = Checksum16.calc(self.pbytes.bytes)
        logger.info('Inserted Checksum: %s', self)
        return self.header['checksum']

    def decode(self):
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


class DATA(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.data = BitStream()
        logger.info('Created DATA Packet: %s', self)

    def encode(self):
        self.pbytes = pack(self.bitfmt, **self.header)  # Fake Packet for Checksum to be made
        self.pbytes.append(self.data)
        self.header['checksum'] = self.calc_checksum()
        self.pbytes = pack(self.bitfmt, **self.header)  # Final Packet with Checksum and Data
        self.pbytes.append(self.data)
        self.binary = self.pbytes.bin
        logger.info('Encode DATA Packet: %s Checksum: %s', self, self.header['checksum'])
        return self

    def calc_checksum(self):
        self.header['checksum'] = Checksum16.calc(self.pbytes.bytes)
        logger.info('Inserted Checksum: %s', self)
        return self.header['checksum']


class ACK(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.header['ack'] = 1
        logger.info('Created ACK Packet: %s', self)


class SYN(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.header['syn'] = 1
        logger.info('Created SYN Packet: %s', self)


class SYNACK(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.header['syn'] = 1
        self.header['ack'] = 1
        logger.info('Created SYN-ACK Packet: %s', self)


class FIN(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.header['fin'] = 1
        logger.info('Created FIN Packet: %s', self)


class FINACK(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.header['fin'] = 1
        self.header['ack'] = 1
        logger.info('Created FIN-ACK Packet: %s', self)


class CONVERT(Packet):
    def __init__(self, binary):
        Packet.__init__(self)
        self.header['srcport'] = int(binary[0:16], 2)
        self.header['dstport'] = int(binary[16:32], 2)
        self.header['seqnum'] = int(binary[32:64], 2)
        self.header['acknum'] = int(binary[64:96], 2)
        self.header['dataoffset'] = int(binary[96:100], 2)
        self.header['reserved'] = int(binary[100:106], 2)
        self.header['urg'] = int(binary[106], 2)
        self.header['ack'] = int(binary[107], 2)
        self.header['psh'] = int(binary[108], 2)
        self.header['rst'] = int(binary[109], 2)
        self.header['syn'] = int(binary[110], 2)
        self.header['fin'] = int(binary[111], 2)
        self.header['window'] = int(binary[112:128], 2)
        self.header['checksum'] = int(binary[128:144], 2)
        self.header['urgtptr'] = int(binary[144:160], 2)




