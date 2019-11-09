from statemachine import StateMachine, State
from packet import *
import socket
import struct


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
        logger.info('Entered State: %s', self.current_state)

    def on_enter_established(self):
        logger.info('Entered State: %s', self.current_state)

    def on_enter_finwait1(self):
        logger.info('Entered State: %s', self.current_state)

    def on_enter_finwait2(self):
        logger.info('Entered State: %s', self.current_state)

    def on_enter_timewait(self):
        logger.info('Entered State: %s', self.current_state)

    def on_enter_closed(self):
        logger.info('Entered State: %s', self.current_state)

    def on_enter_complete(self):
        logger.info('Entered State: %s', self.current_state)


class StateHandler:
    def __init__(self, adr, sp, cp, fn):
        self.states = States()
        self.adr = adr
        self.sp = sp
        self.cp = cp
        self.fn = open(fn, 'wb')
        self.UDPsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.run()

    def receive(self):
        (packet, (adr, sp)) = self.UDPsocket.recvfrom(2048)

    def run(self):
        while not self.states.is_complete:
            if self.states.is_init:
                packet = SYN()
                packet.header['srcport'] = self.sp
                packet.header['dstport'] = self.cp
                self.UDPsocket.sendto(packet.encode().bin.encode('ascii'), ('127.0.0.1', self.sp))
                self.states.run('cycle')
            elif self.states.is_synsent:

                self.states.run('cycle')
            elif self.states.is_established:
                self.states.run('cycle')
            elif self.states.is_finwait1:
                self.states.run('cycle')
            elif self.states.is_finwait2:
                self.states.run('cycle')
            elif self.states.is_timewait:
                self.states.run('cycle')
            elif self.states.is_closed:
                self.states.run('cycle')

test = StateHandler('127.0.0.1', 1, 1, 1)

