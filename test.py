# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from packet import *
from bitstring import pack, BitArray
from crccheck.checksum import Checksum16

pkt = SYN()

pkt.encode()

print(pkt.header['checksum'])



crc = Checksum16.calc(BitArray(bin=pkt.binary))

print(crc)

print(pkt.binary)
print(pkt.header)

