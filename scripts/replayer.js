let views = new Map()

function replayCollectViews() {
    instrumentOverload('android.view.View', 'onDraw', ['android.graphics.Canvas'], function (canvas) {
        this.onDraw(canvas);
        views.set(getViewFullSignature(this), Java.retain(this));
    });
    instrumentOverload('android.view.View', 'draw', ['android.graphics.Canvas'], function (canvas) {
        this.draw(canvas);
        views.set(getViewFullSignature(this), Java.retain(this));
    });
    instrumentOverload('android.view.View', 'setVisibility', ['int'], function (visibility) {
        this.setVisibility(visibility);
        if (visibility === 0) {
            views.set(getViewFullSignature(this), Java.retain(this))
        } else {
            views.delete(getViewFullSignature(this));
        }
    });
    send('-- Collect views instrument finished')
}

const MotionEvent = Java.use('android.view.MotionEvent')
const KeyEvent = Java.use('android.view.KeyEvent')

function replayMotionEvent(event) {
    const viewSignature = event['view']
    const view = views.get(viewSignature)
    if (view) {
        //const location = Java.array('int', [0, 0])
        //view.getLocationOnScreen(location)
        send('find view!')
        Java.scheduleOnMainThread(function () {
            const motionEvent = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'int')
                .call(MotionEvent, Long.parseLong(event['downTime']), Long.parseLong(event['eventTime']), event['action'], event['x'], event['y'], event['metaState'])
            // send('send motionevent! ' + motionEvent)
            view.dispatchTouchEvent(motionEvent)
        })
    } else {
        send('view not found! ' + viewSignature)
    }
    return view !== undefined
}

function replayKeyEvent(event) {
    const viewSignature = event['view']
    const view = views.get(viewSignature)
    if (view) {
        send('find view!')
        Java.scheduleOnMainThread(function () {
            const keyEvent = KeyEvent.$new.overload('long', 'long', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int')
                .call(KeyEvent, Long.parseLong(event['downTime']), Long.parseLong(event['eventTime']), event['action'], event['code'], event['repeat'], event['metaState'], event['deviceId'], event['scancode'], event['flags'], event['source'])
            view.dispatchKeyEvent(keyEvent)
        })
    } else {
        send('view not found! ' + viewSignature)
    }
    return view !== undefined
}

function replayLocationActive(data) {
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider);
        if (location === null) {
            return location;
        }
        if (data.hasOwnProperty(provider)) {
            let index = data[provider].index;
            if (index >= data[provider].values.length) {
                index = data[provider].values.length - 1;
            }
            const value = data[provider].values[index];
            location.mLatitude = value.latitude;
            location.mLongitude = value.longitude;
            location.mBearing = value.bearing;
            location.mSpeed = value.speed;
            location.mAltitude = value.altitude;
            location.mAccuracy = value.accuracy;
        }
        return location
    });
}

function replayLocationPassive(className, data) {
    instrument(className, 'onLocationChanged', function (location) {
        if (location === null) {
            return null
        }
        let index = data.index;
        if (index >= data.values.length) {
            index = data.values.length - 1;
        }
        const value = data.values[index];
        location.mLatitude = value.latitude;
        location.mLongitude = value.longitude;
        location.mBearing = value.bearing;
        location.mSpeed = value.speed;
        location.mAltitude = value.altitude;
        location.mAccuracy = value.accuracy;
        return this.onLocationChanged(location)
    });
}

function replaySensor(className, event) {
    // TODO
}

rpc.exports = {
    replayCollectViews,
    replayMotionEvent,
    replayKeyEvent,
    replayLocationActive,
    replayLocationPassive,
    replaySensor
}