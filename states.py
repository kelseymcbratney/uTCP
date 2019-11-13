# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from statemachine import StateMachine, State
from bitstring import pack, BitArray, BitStream
from packet import *
from log import *
import socket
import random
import time


class States(StateMachine):
    init = State('init', initial=True)
    synsent = State('synsent')
    established = State('established')
    finwait1 = State('finwait1')
    finwait2 = State('finwait2')
    timewait = State('timewait')
    closed = State('closed')
    complete = State('complete')

    cycle = init.to(synsent) | synsent.to(established) | established.to(finwait1) | finwait1.to(finwait2) | \
            finwait2.to(timewait) | timewait.to(closed) | closed.to(complete)

    def on_enter_synsent(self):
        logger.info('Entered State: SYNSENT')

    def on_enter_established(self):
        logger.info('Entered State: ESTABLISHED')

    def on_enter_finwait1(self):
        logger.info('Entered State: FINWAIT1')

    def on_enter_finwait2(self):
        logger.info('Entered State: FINWAIT2')

    def on_enter_timewait(self):
        logger.info('Entered State: TIMEWAIT')

    def on_enter_closed(self):
        logger.info('Entered State: CLOSED')

    def on_enter_complete(self):
        logger.info('Entered State: COMPLETE')


class StateHandler:
    def __init__(self, adr, sp, cp, fn):
        self.states = States()
        self.adr = adr
        self.sp = sp
        self.cp = cp
        self.file = open(fn, 'rb')
        self.TIMEOUT = 5
        self.UDPsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.UDPsocket.settimeout(self.TIMEOUT)
        self.UDPsocket.bind(('', self.cp))
        self.previousSeqnum = 0
        self.previousACK = 0
        self.previousSentACK = 0
        self.previousSentSeqnum = 0
        self.windowSize = 0

        self.run()

    def receive(self):
        (incpacket, (adr, sp)) = self.UDPsocket.recvfrom(2048)
        logger.info("INCOMING RAW BYTES: %s", incpacket)
        incbits = BitStream(incpacket)
        incbits = incbits.bin
        logger.info("INCOMING RAW BITS: %s", incbits)
        if incbits[110] == '1':  # SYN bit
            if incbits[107] == '1':  # ACK Bit
                packet = SYNACK()
                packet.binary = incbits
                packet.decode()
                print("incoming header")
                print(packet.header)
                self.previousSeqnum = packet.header['seqnum']
                self.previousACK = packet.header['acknum']
                self.windowSize = packet.header['window']
                logger.info("Received (SYN)ACK: %s", packet.header)
                return packet
        elif incbits[111] == '1':  # FIN
            if incbits[107] == '1':  # ACK
                packet = FINACK()
                packet.binary = incbits
                packet.decode()
                return packet
        elif incbits[107] == '1':  # ACK (Data)
            packet = Packet()
            packet.binary = incbits
            packet.decode()
            self.previousSeqnum = packet.header['seqnum']
            self.previousACK = packet.header['acknum']
            logger.info("Received ACK: %s", packet.header)
            return packet

    def run(self):
        time.sleep(1)
        while not self.states.is_complete:
            if self.states.is_init is True:  # SEND SYN PACKET (Default) -- SEND SYN
                packet = SYN()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['seqnum'] = random.randint(1, 50000)
                self.previousSentSeqnum = packet.header['seqnum']
                packet.header['dataoffset'] = 5

                self.UDPsocket.sendto(packet.encode().pbytes.bytes, (self.adr, self.sp))
                logger.info("Sending SYN: %s", packet.header)
                self.states.run('cycle')
            elif self.states.is_synsent is True:  # SYNSENT STATE -- SENDS ACK for (SYN-ACK)
                rcvpacket = self.receive()  # RECEIVE SYN-ACK

                packet = ACK()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['dataoffset'] = 5
                packet.header['seqnum'] = self.previousSentSeqnum + 1
                self.previousSentSeqnum = packet.header['seqnum']
                packet.header['acknum'] = self.previousACK + 1
                self.previousACK = packet.header['acknum']


                self.UDPsocket.sendto(packet.encode().pbytes.bytes, (self.adr, self.sp))  # SEND ACK for SYN-ACK
                logger.info("Sending ACK: %s", packet.header)
                self.states.run('cycle')

            elif self.states.is_established is True:  # ESTABLISHED STATE
                self.receive()
                databytes = self.file.read(1000)
                if len(databytes) == 0:
                    logger.info("Sending FIN")
                    self.states.run('cycle')
                    break
                packet = DATA()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['dataoffset'] = 5
                packet.header['seqnum'] = self.previousACK
                packet.header['acknum'] = self.previousSentSeqnum + len(databytes)
                packet.data = databytes
                self.UDPsocket.sendto(packet.encode().pbytes.bytes, (self.adr, self.sp))  # SEND DATA
                logger.info("Sending Data: %s", packet.header)


                #  SEND DATA HERE




            elif self.states.is_finwait1 is True:  # FINWAIT1 STATE
                self.states.run('cycle')

            elif self.states.is_finwait2 is True:  # FINWAIT2 STATE
                self.states.run('cycle')

            elif self.states.is_timewait is True:  # TIMEWAIT STATE
                self.states.run('cycle')

            elif self.states.is_closed is True:  # CLOSED STATE
                self.states.run('cycle')


