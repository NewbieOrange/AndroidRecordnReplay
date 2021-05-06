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
        self.script = None
        self.stream = None

    def record(self):
        self.record_device_info()
        self.record_frida()
        # self.record_events()

    def record_device_info(self):
        screen_width, screen_height = self.device.window_size()
        logging.info('{"event":"DeviceInfo","x":%s,"y":%s}' % (screen_width, screen_height))

    def record_frida(self):
        with open('scripts/recorder.js', 'r') as f:
            self.script = script.Script(self.session, f.read())
        self.script.set_on_message(self.on_message)
        self.script.rpc.record_touch_and_key()
        self.script.rpc.record_location()
        self.script.rpc.record_sensor()
        self.script.rpc.record_time_sync()

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
            logging.info(msg['payload'].rstrip('\n'))
        else:
            logging.info(msg)

    def close(self):
        self.script.rpc.flush_buffer()
        self.session.detach()
        self.stream.close()


def main(argv):
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(argv[0], 'w', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    frida_device = frida.get_usb_device()
    pid = frida_device.spawn(argv[1])
    session = frida_device.attach(pid)
    session.enable_jit()
    adb_device = adb.device()
    recorder = Recorder(session, adb_device)
    recorder.record()
    frida_device.resume(pid)

    sys.stdin.read()  # Wait for exit
    recorder.close()


if __name__ == '__main__':
    main(sys.argv[1:])
