import signal

class Termination:
    def __init__(self, signals):
        self.__request_flag = False

        for sig in signals:
            if type(sig) is str and hasattr(signal, sig):
                signal.signal(getattr(signal, sig), self.__set_flag)
                # TODO: LOG
                print(f'LOG: signal \'{sig}\' added to Termination object')
            elif type(sig) is int:
                signal.signal(sig, self.__set_flag)
                # TODO: LOG
                print(f'LOG: signal {sig} added to Termination object')
            else:
                print(f'WARNING: signal {sig} not added to Termination object')
                pass

    def __set_flag(self, signum, frame):
        self.__request_flag = True

    def requested(self):
        return self.__request_flag