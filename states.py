from statemachine import StateMachine, State


class uTCP(StateMachine):
    synsent = State('synsent', initial=True)
    established = State('established')
    finwait1 = State('finwait1')
    finwait2 = State('finwait2')
    timewait = State('timewait')
    closed = State('closed')

    synack = synsent.to(established)





statemachine = uTCP()

statemachine.synack()

print(statemachine.current_state)


class States():
    def __init__(self):
        pass


