import sys

import adbutils
import frida

import script


class Recorder:
    def __init__(self, session: frida.core.Session, device: adbutils.AdbDevice):
        self.session = session
        self.device = device

    def record(self):
        self.record_adb()
        self.record_frida()

    def record_adb(self):
        self.device.shell('getevent -tt')

    def record_frida(self):
        with open('recorder.js', 'r') as f:
            s = script.Script(session, f.read())
        s.set_on_message(self.on_message)
        s.rpc.record()

    def on_message(self, msg: dict, _):
        if msg['type'] == 'send':
            print(msg['payload'])
        else:
            print(msg)

    def close(self):
        print('closed')
        self.session.detach()


if __name__ == '__main__':
    session = frida.get_usb_device().attach('com.exatools.sensors')
    recorder = Recorder(session)
    recorder.record()
    sys.stdin.read()  # pause for logs
