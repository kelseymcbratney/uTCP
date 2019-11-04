from bitstring import pack, BitArray
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
        self.bin = None
        logger.info('Created Packet: %s', self)

    def encode(self):
        self.bin = pack(self.bitfmt, **self.header).bin
        self.header['checksum'] = self.calc_checksum()
        self.bin = self.bin[:128] + BitArray(uint=self.header['checksum'], length=16).bin + self.bin[144:]
        logger.info('Encoded Packet: %s', self)
        return self

    def decode(self):
        self.header['srcport'] = int(self.bin[0:16], 2)
        self.header['dstport'] = int(self.bin[16:32], 2)
        self.header['seqnum'] = int(self.bin[32:64], 2)
        self.header['acknum'] = int(self.bin[64:96], 2)
        self.header['dataoffset'] = int(self.bin[96:100], 2)
        self.header['reserved'] = int(self.bin[100:106], 2)
        self.header['urg'] = int(self.bin[106], 2)
        self.header['ack'] = int(self.bin[107], 2)
        self.header['psh'] = int(self.bin[108], 2)
        self.header['rst'] = int(self.bin[109], 2)
        self.header['syn'] = int(self.bin[110], 2)
        self.header['fin'] = int(self.bin[111], 2)
        self.header['window'] = int(self.bin[112:128], 2)
        self.header['checksum'] = int(self.bin[128:144], 2)
        self.header['urgtptr'] = int(self.bin[144:160], 2)
        logger.info('Decoded Packet: %s', self)
        return self

    def calc_checksum(self):
        self.header['checksum'] = Checksum16.calc(BitArray(bin=pack(self.bitfmt, **self.header).bin))
        logger.info('Inserted Checksum: %s', self)
        return self.header['checksum']

    def debug(self):
        print(self.header)


class DATA(Packet):
    def __init__(self):
        Packet.__init__(self)
        self.data = None
        logger.info('Created DATA Packet: %s', self)


    def encode(self):
        self.bin = pack(self.bitfmt, **self.header).bin
        self.bin += self.data
        self.header['checksum'] = self.calc_checksum()
        self.bin = self.bin[:128] + BitArray(uint=self.header['checksum'], length=16).bin + self.bin[144:]
        logger.info('Encoded DATA Packet: %s', self)
        return self

    def calc_checksum(self):
        self.header['data'] = 0
        self.bin = pack(self.bitfmt, **self.header).bin + self.data
        self.bin = self.bin[:128] + BitArray(uint=self.header['checksum'], length=16).bin + self.bin[144:]
        logger.info('Encoded DATA Packet: %s', self)
        pass


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



