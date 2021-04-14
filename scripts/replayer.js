let views = {}

function replayCollectViews() {
    instrumentOverload('android.view.View', 'draw', ['android.graphics.Canvas'], function (canvas) {
        this.draw(canvas)
        views[getViewFullSignature(this)] = Java.retain(this)
    })
    instrumentOverload('android.view.View', 'dispatchDraw', ['android.graphics.Canvas'], function (canvas) {
        this.dispatchDraw(canvas)
        views[getViewFullSignature(this)] = Java.retain(this)
    })
    // instrumentOverload('android.view.View', 'setVisibility', ['int'], function (visibility) {
    //     this.setVisibility(visibility)
    //     if (visibility === 0) {
    //         views[getViewFullSignature(this)] = Java.retain(this)
    //     // } else {
    //         // delete views[getViewFullSignature(this)]
    //     }
    // })
    send('-- Collect views instrument finished')
}

const MotionEvent = Java.use('android.view.MotionEvent')
const KeyEvent = Java.use('android.view.KeyEvent')
const MotionEventObtain = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'float', 'float', 'int', 'float', 'float', 'int', 'int')

function replayMotionEvent(event) {
    const viewSignature = event['view']
    const view = views[viewSignature]
    if (view) {
        //const location = Java.array('int', [0, 0])
        //view.getLocationOnScreen(location)
        // send('find view!')
        Java.scheduleOnMainThread(function () {
            const adjustedCoord = adjustCoordinates(view, event['x'], event['y'], event['width'], event['height'])
            const motionEvent = MotionEventObtain.call(MotionEvent, Long.parseLong(event['downTime']), Long.parseLong(event['eventTime']),
                event['action'], adjustedCoord.x, adjustedCoord.y, event['pressure'], event['size'],
                event['metaState'], event['xPrecision'], event['yPrecision'], event['deviceId'], event['edgeFlags'])
            view.onTouchEvent(motionEvent)
        })
    } else {
        send('view not found! ' + viewSignature)
    }
    return view !== undefined
}

function replayKeyEvent(event) {
    const viewSignature = event['view']
    const view = views[viewSignature]
    if (view) {
        // send('find view!')
        Java.scheduleOnMainThread(function () {
            const keyEvent = KeyEvent.$new.overload('long', 'long', 'int', 'int', 'int', 'int', 'int', 'int', 'int', 'int')
                .call(KeyEvent, Long.parseLong(event['downTime']), Long.parseLong(event['eventTime']),
                    event['action'], event['code'], event['repeat'], event['metaState'], event['deviceId'],
                    event['scancode'], event['flags'], event['source'])
            view.dispatchKeyEvent(keyEvent)
        })
        // } else {
        //     send('view not found!')
    }
    return view !== undefined
}

const locationProvider = {}, locationListener = {}

function replayLocationActive() {
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        if (location === null) {
            return location
        }
        const value = locationProvider[provider]
        if (value) {
            location.setLatitude(value.latitude)
            location.setLongitude(value.longitude)
            location.setBearing(value.bearing)
            location.setSpeed(value.speed)
            location.setAltitude(value.altitude)
            location.setAccuracy(value.accuracy)
        }
        return location
    });
}

function replayLocationPassive(className) {
    instrument(className, 'onLocationChanged', function (location) {
        if (location.getProvider() === 'fake') {
            location.setProvider('')
            this.onLocationChanged(location)
        }
    });
}

function replayLocationPassiveAll() {
    const classLocationListener = Class.forName('android.location.LocationListener')
    Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
        onMatch(name, handle) {
            if (!name.startsWith('android.')) { // skip Android library classes
                const classHandle = Java.cast(handle, Class)
                if (classLocationListener.isAssignableFrom(classHandle)) {
                    replayLocationPassive(name)
                    locationListener[name] = Java.retain(handle)
                }
            }
        },
        onComplete() {
            send('-- Location instrumentation finished')
        }
    })
    Java.perform(() => {
        instrumentOverload('android.location.LocationManager', 'requestLocationUpdates', ['java.lang.String', 'long', 'float', 'android.location.LocationListener'], function (provider, minTime, minDistance, listener) {
            replayLocationPassive(listener.$className)
            locationListener[listener.$className] = Java.retain(listener)
            return this.requestLocationUpdates(provider, minTime, minDistance, listener)
        });
    })
}

function replayLocation() {
    replayLocationActive()
    replayLocationPassiveAll()
}

const Location = Java.use('android.location.Location')

function parseLocation(value) {
    const location = Location.$new('fake')
    location.setLatitude(value.latitude)
    location.setLongitude(value.longitude)
    location.setBearing(value.bearing)
    location.setSpeed(value.speed)
    location.setAltitude(value.altitude)
    location.setAccuracy(value.accuracy)
    return location
}

function setReplayLocationActive(provider, value) {
    locationProvider[provider] = value
}

function setReplayLocationPassive(className, value) {
    const listener = locationListener[className]
    if (listener) {
        listener.onLocationChanged(parseLocation(value))
        send('find')
    } else {
        send('gps not found ' + className)
    }
}

function replaySensor(className, event) {
    // TODO
}

rpc.exports = {
    replayCollectViews,
    replayMotionEvent,
    replayKeyEvent,
    replayLocation,
    setReplayLocationActive,
    setReplayLocationPassive
}
