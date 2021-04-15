import time
import json
import sys

import frida
import uiautomator2 as u2

import script


class Replayer:
    def __init__(self, raw: bool, session: frida.core.Session, frida_device: frida.core.Device, pid, u2_device: u2.Device):
        self.raw = raw
        self.session = session
        self.frida_device = frida_device
        self.pid = pid
        self.u2_device = u2_device
        self.screen_width, self.screen_height = u2_device.window_size()
        self.original_screen_width, self.original_screen_height = None, None
        with open('scripts/replayer.js', 'r') as f:
            s = script.Script(self.session, f.read())
        s.set_on_message(self.on_message)
        self.rpc = s.rpc

    def replay(self, data):
        self.rpc.replay_collect_views()
        self.rpc.replay_location()
        self.rpc.replay_sensor()
        self.frida_device.resume(self.pid)
        for i in reversed(range(0, 3)):
            print('-- Waiting for views: %d' % i)
            time.sleep(1)
        start_time = None
        start_real_time = time.time()
        for event in data:
            if not event.startswith('{'):
                continue
            event = json.loads(event)
            if event['event'] == 'DeviceInfo':
                self.original_screen_width, self.original_screen_height = event['x'], event['y']
                continue
            elif event['event'] == 'TimeEvent':
                start_time = int(event['eventTime'])
                continue
            sleep_time = (int(event['eventTime']) - start_time) / 1000 - time.time() + start_real_time
            if sleep_time > 0:
                time.sleep(sleep_time)
            if event['event'] == 'MotionEvent':
                if self.raw or not self.rpc.replay_motion_event(event):  # widget failed, fallback to coord
                    if event['action'] == 0:
                        self.u2_device.touch.down(*self.adjust_raw_coord(event['rawX'], event['rawY']))
                    elif event['action'] == 1:
                        self.u2_device.touch.up(*self.adjust_raw_coord(event['rawX'], event['rawY']))
                    elif event['action'] == 2:
                        self.u2_device.touch.move(*self.adjust_raw_coord(event['rawX'], event['rawY']))
            elif event['event'] == 'KeyEvent':
                if self.raw or not self.rpc.replay_key_event(event):  # widget failed, fallback to adb shell input
                    if event['action'] == 0:
                        self.u2_device.keyevent(str(event['code']))
            elif event['event'] == 'LocationEvent':
                if event['provider']:
                    self.rpc.set_replay_location_active(event['provider'], event)
                else:
                    self.rpc.set_replay_location_passive(event['listener'], event)
            elif event['event'] == 'SensorEvent':
                self.rpc.set_replay_sensor_passive(event['listener'], event)
        time.sleep(1)

    def adjust_raw_coord(self, x, y):
        return x * self.screen_width / self.original_screen_width, y * self.screen_height / self.original_screen_height

    def on_message(self, msg: dict, _):
        if msg['type'] == 'send':
            print(msg['payload'])
        else:
            print(msg)


def main():
    frida_device = frida.get_usb_device()
    pid = frida_device.spawn(sys.argv[2])
    session = frida_device.attach(pid)
    session.enable_jit()
    u2_device = u2.connect()

    replayer = Replayer(False, session, frida_device, pid, u2_device)
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        replayer.replay(f.read().splitlines())


if __name__ == '__main__':
    main()
