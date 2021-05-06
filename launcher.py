import recorder
import replayer
import sys

# com.accuweather.android
if __name__ == '__main__':
    print('Record(c) or replay(p)?: ', end='')
    mode = sys.stdin.readline().rstrip('\n')
    print('App package name: ', end='')
    app = sys.stdin.readline().rstrip('\n')
    print('Record index #', end='')
    idx = sys.stdin.readline().rstrip('\n')
    if mode == 'c':
        recorder.main(['./records/%s.%s.txt' % (app, idx), app])
    else:
        replayer.main(['./records/%s.%s.txt' % (app, idx), app])
