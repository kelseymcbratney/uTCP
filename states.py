# Kelsey McBratney
# Computer Networking A365
# TCP Over UDP Client
from statemachine import StateMachine, State
from packet import *
from log import *
import socket
import random
import time


class States(StateMachine):  # Creates State Machine from python-statemachine library
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

    def on_enter_synsent(self):  # Creates Log when Entering Synsent State
        logger.info('Entered State: SYNSENT')

    def on_enter_established(self):  # Creates Log when Entering Established State
        logger.info('Entered State: ESTABLISHED')

    def on_enter_finwait1(self):  # Creates Log when Entering Finwait1 State
        logger.info('Entered State: FINWAIT1')

    def on_enter_finwait2(self):  # Creates Log when Entering Finwait2 State
        logger.info('Entered State: FINWAIT2')

    def on_enter_timewait(self):  # Creates Log when Entering Timewait State
        logger.info('Entered State: TIMEWAIT')

    def on_enter_closed(self):  # Creates Log when Entering Closed State
        logger.info('Entered State: CLOSED')

    def on_enter_complete(self):  # Creates Log when Entering Complete State
        logger.info('Entered State: COMPLETE')


class StateHandler:
    def __init__(self, adr, sp, cp, fn):  # Main Handler of TCP Transfer, Relies on State Machine
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
        self.remainingWindow = 0

        self.run()  # Run Method on Start

    def receive(self):  # Receives and Handles all Incoming Packets
        (incpacket, (adr, sp)) = self.UDPsocket.recvfrom(2048)
        if sp != self.sp:
            logger.info("Received Data from Wrong Port: %s - DISCARDING PACKET", sp)
            return

        incbits = BitStream(incpacket)
        incbits = incbits.bin
        if incbits[110] == '1':  # SYN bit
            if incbits[107] == '1':  # ACK Bit
                packet = SYNACK()
                packet.binary = incbits
                packet.decode()
                self.windowSize = packet.header['window']  # Saves Initial Window
                if self.error_check(packet) is True:
                    return
                self.previousSeqnum = packet.header['seqnum']
                self.previousACK = packet.header['acknum']
                self.remainingWindow = packet.header['window']
                logger.info("Received (SYN)ACK: %s", packet.header)
                return packet
        elif incbits[111] == '1':  # FIN
            if incbits[107] == '1':  # ACK
                packet = FINACK()
                packet.binary = incbits
                packet.decode()
                if self.error_check(packet) is True:
                    return
                self.previousSeqnum = packet.header['seqnum']
                self.previousACK = packet.header['acknum']
                logger.info("Received FIN-ACK: %s", packet.header)
                return packet
        elif incbits[107] == '1':  # ACK
            packet = Packet()
            packet.binary = incbits
            packet.decode()
            if self.error_check(packet) is True:
                return
            self.previousSeqnum = packet.header['seqnum']
            self.previousACK = packet.header['acknum']

            logger.info("Received ACK: %s", packet.header)
            return packet

    def send(self, packet):
        self.UDPsocket.sendto(packet.encode(), (self.adr, self.sp))
        pass

    def run(self):
        while not self.states.is_complete:
            if self.states.is_init is True:  # SEND SYN PACKET (Default) -- SEND SYN
                packet = SYN()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['seqnum'] = random.randint(1, 50000)
                packet.header['dataoffset'] = 5
                self.previousSentSeqnum = packet.header['seqnum']

                self.send(packet)
                logger.info("Sending SYN: %s", packet.header)
                self.states.run('cycle')
            elif self.states.is_synsent is True:  # SYNSENT STATE -- SENDS ACK for (SYN-ACK)
                incpacket = self.receive()  # RECEIVES SYN-ACK
                packet = ACK()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['seqnum'] = self.previousSentSeqnum + 1
                packet.header['acknum'] = self.previousACK + 1
                packet.header['dataoffset'] = 5
                self.previousSentSeqnum = packet.header['seqnum']
                self.previousACK = packet.header['acknum']

                self.send(packet)  # SENDS ACK
                logger.info("Sending ACK: %s", packet.header)
                if (incpacket) is not None:
                    self.states.run('cycle')
            elif self.states.is_established is True:  # ESTABLISHED STATE -- SENDS DATA AND FIN
                self.receive()
                databytes = self.file.read(1452)
                if len(databytes) == 0:  # SENDS FIN WHEN NO MORE DATA TO SEND
                    packet = FIN()
                    packet.header['srcport'] = self.cp
                    packet.header['dstport'] = self.sp
                    packet.header['seqnum'] = self.previousACK
                    packet.header['acknum'] = self.previousSentSeqnum
                    packet.header['dataoffset'] = 5

                    self.send(packet)
                    logger.info("Sending FIN: %s", packet.header)
                    self.states.run('cycle')
                    break

                packet = DATA()
                packet.header['srcport'] = self.cp
                packet.header['dstport'] = self.sp
                packet.header['dataoffset'] = 5
                packet.header['seqnum'] = self.previousACK
                packet.header['acknum'] = self.previousSentSeqnum + len(databytes)
                self.previousSentACK = packet.header['acknum']
                packet.data = databytes
                self.send(packet)  # SENDS DATA PACKET
                logger.info("Sending Data: %s", packet.header)

            elif self.states.is_finwait1 is True:  # FINWAIT1 STATE -- RECEIVES FIN-ACK
                incpacket = self.receive() # Receives FIN-ACK
                if (incpacket) is not None:
                    self.states.run('cycle')

            elif self.states.is_finwait2 is True:  # FINWAIT2 STATE -- RECEIVES FIN
                self.states.run('cycle')

            elif self.states.is_timewait is True:  # TIMEWAIT STATE
                self.states.run('cycle')

            elif self.states.is_closed is True:  # CLOSED STATE
                self.states.run('cycle')

    def error_check(self, packet):  # Takes Incoming Packet and Checks for List of Errors, Handles Appropriately
        if packet.check_checksum() is False:
            logger.info("Received Bad Checksum: %s - DISCARDING PACKET", packet.header['checksum'])
            return True
        if packet.header['srcport'] != self.sp:
            logger.info("Incoming Source Port is packet is not Expected Port: %s - CLOSING CLIENT", self.sp)
            exit(1)
        if packet.header['dstport'] != self.cp:
            logger.info("Incoming Destination Port is packet is not Expected Port: %s - DISCARDING PACKET", self.cp)
            return True
        if packet.header['dataoffset'] != 5:
            logger.info("Invalid Data Offset: %s - CLOSING CLIENT", packet.header)
            exit(1)
        if packet.header['reserved'] != 0:
            logger.info("Invalid Reserve Flag: %s - CLOSING CLIENT", packet.header['reserved'])
            exit(1)
        if packet.header['urg'] != 0:
            logger.info("Invalid Urgent Flag: %s - CLOSING CLIENT", packet.header['urg'])
            exit(1)
        if packet.header['psh'] != 0:
            logger.info("Invalid Push Flag: %s - CLOSING CLIENT", packet.header['psh'])
            exit(1)
        if packet.header['rst'] != 0:
            logger.info("Invalid Reset Flag: %s - CLOSING CLIENT", packet.header['rst'])
            exit(1)
        if packet.header['window'] == 0 or packet.header['window'] != self.windowSize:
            logger.info("Invalid Window Size: %s - CLOSING CLIENT", packet.header['window'])
            exit(1)
        if packet.header['urgtptr'] != 0:
            logger.info("Invalid Urgent Pointer: %s - CLOSING CLIENT", packet.header['urgtptr'])
            exit(1)
