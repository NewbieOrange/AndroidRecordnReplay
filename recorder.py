import logging
import sys

from adbutils import adb
import adbutils
import frida

import script


class Recorder:
    def __init__(self, session: frida.core.Session, device: adbutils.AdbDevice):
        self.session = session
        self.device = device
        self.stream = None

    def record(self):
        self.record_frida()
        self.record_events()

    def record_frida(self):
        with open('scripts/recorder.js', 'r') as f:
            s = script.Script(self.session, f.read())
        s.set_on_message(self.on_message)
        s.rpc.record()

    def record_events(self):
        self.stream = self.device.shell('getevent -tt', stream=True)
        while True:
            buffer = b''
            while True:
                ch = self.stream.conn.recv(1)
                if not ch or ch == b'\n':
                    break
                buffer += ch
            logging.info(buffer.decode())

    def on_message(self, msg: dict, _):
        if msg['type'] == 'send':
            logging.info(msg['payload'])
        else:
            logging.info(msg)

    def close(self):
        self.session.detach()
        self.stream.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler('output.txt'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    device = adb.device()
    # device.sync.push('lib/frida-server', '/data/local/tmp/frida-server')
    # device.shell('/data/local/tmp/frida-server &')

    session = frida.get_usb_device().attach('com.google.android.apps.messaging')
    recorder = Recorder(session, device)
    recorder.record()


if __name__ == '__main__':
    main()
