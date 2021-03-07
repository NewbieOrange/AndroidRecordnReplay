import uiautomator2 as u2


class Replayer:
    def __init__(self, device: u2.Device):
        self.device = device

    def replay(self, data):
        event_time = None
        for event in data:
            if event.startswith('MotionEvent'):
                motion = dict(token.split('=') for token in event[len('MotionEvent { '):-len(' }')].split(', '))
                print(motion)
                sleep_time = (int(motion['eventTime']) - event_time) / 1000 if event_time else 0
                print('sleep for ' + str(sleep_time) + 'sec')
                self.device.touch.sleep(sleep_time)
                if motion['action'] == 'ACTION_DOWN':
                    self.device.touch.down(float(motion['x[0]']), float(motion['y[0]']))
                elif motion['action'] == 'ACTION_UP':
                    self.device.touch.up(float(motion['x[0]']), float(motion['y[0]']))
                elif motion['action'] == 'ACTION_MOVE':
                    self.device.touch.move(float(motion['x[0]']), float(motion['y[0]']))
                event_time = int(motion['eventTime'])


def main():
    device = u2.connect()
    print(device.info)

    replayer = Replayer(device)
    with open('output.txt', 'r') as f:
        replayer.replay(f.read().splitlines())


if __name__ == '__main__':
    main()
