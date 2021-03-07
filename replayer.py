import time

import frida
import uiautomator2 as u2

import script


class Replayer:
    def __init__(self, session: frida.core.Session, device: u2.Device):
        self.session = session
        self.device = device
        with open('scripts/replayer.js', 'r') as f:
            s = script.Script(self.session, f.read())
        s.set_on_message(self.on_message)
        self.rpc = s.rpc

    def replay(self, data):
        event_time = None
        for event in data:
            if event.startswith('MotionEvent'):
                motion = dict(token.split('=') for token in event[len('MotionEvent { '):-len(' }')].split(', '))
                print(motion)
                sleep_time = (int(motion['eventTime']) - event_time) / 1000 if event_time else 0
                print('sleep for ' + str(sleep_time) + 'sec')
                time.sleep(sleep_time)
                if motion['action'] == 'ACTION_DOWN':
                    self.device.touch.down(float(motion['x[0]']), float(motion['y[0]']))
                elif motion['action'] == 'ACTION_UP':
                    self.device.touch.up(float(motion['x[0]']), float(motion['y[0]']))
                elif motion['action'] == 'ACTION_MOVE':
                    self.device.touch.move(float(motion['x[0]']), float(motion['y[0]']))
                event_time = int(motion['eventTime'])
            elif event.startswith('KeyEvent'):
                key = dict(token.split('=') for token in event[len('KeyEvent { '):-len(' }')].split(', '))
                print(key)
                sleep_time = (int(key['eventTime']) - event_time) / 1000 if event_time else 0
                print('sleep for ' + str(sleep_time) + 'sec')
                time.sleep(sleep_time)
                # TODO: input keyboard
            elif event.startswith('LocationResult'):
                self.replay_location(event)

    def replay_location(self, event):
        location = eval(event[len('LocationResult '):])
        print(location)
        # self.rpc.replay_location_passive(location['listener'], location)

    def on_message(self, msg: dict, _):
        if msg['type'] == 'send':
            print(msg['payload'])
        else:
            print(msg)


def main():
    session = frida.get_usb_device().attach('com.yacy.gps')
    device = u2.connect()
    print(device.info)

    replayer = Replayer(session, device)
    with open('output.txt', 'r') as f:
        replayer.replay(f.read().splitlines())


if __name__ == '__main__':
    main()
