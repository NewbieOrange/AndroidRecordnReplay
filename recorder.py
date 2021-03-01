import sys

from adbutils import adb
import adbutils
import frida

import script


class Recorder:
    def __init__(self, session: frida.core.Session, device: adbutils.AdbDevice):
        self.session = session
        self.device = device

    def record(self):
        self.record_events()
        self.record_frida()

    def record_events(self):
        self.device.shell('getevent -tt > /data/local/tmp/recorded_events.txt')

    def record_frida(self):
        with open('recorder.js', 'r') as f:
            s = script.Script(session, f.read())
        s.set_on_message(self.on_message)
        s.rpc.record()

    def extract_events(self):
        self.device.sync.pull('/data/local/tmp/recorded_events.txt', 'recorded_events.txt')

    def on_message(self, msg: dict, _):
        if msg['type'] == 'send':
            print(msg['payload'])
        else:
            print(msg)

    def close(self):
        print('closed')
        self.session.detach()


if __name__ == '__main__':
    device = adb.device()
    device.sync.push('lib/frida-server', '/data/local/tmp/frida-server')
    device.shell('/data/local/tmp/frida-server &')

    session = frida.get_usb_device().attach('com.exatools.sensors')
    recorder = Recorder(session, device)
    recorder.record()
    recorder.extract_events()
    sys.stdin.read()  # pause for logs
