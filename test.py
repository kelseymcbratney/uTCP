from packet import *
from bitstring import pack, BitArray

pkt = SYNACK()



pkt.encode()
print(pkt.bin)

pkt.decode()

print(pkt.header)

