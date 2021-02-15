import frida
import script
import sys


class Recorder:
    def __init__(self, session):
        self.session = session

    def record(self):
        with open('recorder.js', 'r') as f:
            s = script.Script(session, f.read())
        s.rpc.record()


if __name__ == '__main__':
    session = frida.get_usb_device().attach('com.google.android.apps.messaging')
    recorder = Recorder(session)
    recorder.record()
    sys.stdin.read()  # pause for logs
