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
    send('-- Collect views instrument finished')
}

const MotionEvent = Java.use('android.view.MotionEvent')
const KeyEvent = Java.use('android.view.KeyEvent')

function replayMotionEvent(viewSignature, data) {
    const view = views.get(viewSignature)
    if (view) {
        //const location = Java.array('int', [0, 0])
        //view.getLocationOnScreen(location)
        send('find view! ')
        Java.perform(function () {
            Java.scheduleOnMainThread(function () {
                const action = data['action'] === 'ACTION_DOWN' ? 0 : (data['action'] === 'ACTION_UP' ? 1 : 2)
                const args = Java.array('java.lang.Object', [Long.$new(data['eventTime']), Long.$new(data['downTime']), Integer.$new(action), Float.$new(data['x[0]']), Float.$new(data['y[0]']), Integer.$new(0)])
                const motionEvent = obtain.invoke(null, args)
                send('send motionevent! ' + motionEvent)
                view.onTouchEvent(motionEvent)
            })
        })
    }
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
    replayLocationActive,
    replayLocationPassive,
    replaySensor
}
