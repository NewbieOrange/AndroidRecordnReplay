let views = {}

function replayCollectViews() {
    instrumentOverload('android.view.View', 'draw', ['android.graphics.Canvas'], function (canvas) {
        views[getViewFullSignature(this)] = Java.retain(this)
        this.draw(canvas)
    })
    instrumentOverload('android.view.View', 'dispatchDraw', ['android.graphics.Canvas'], function (canvas) {
        views[getViewFullSignature(this)] = Java.retain(this)
        this.dispatchDraw(canvas)
    })
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
    location.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos())
    return location
}

function setReplayLocationActive(provider, value) {
    locationProvider[provider] = value
}

let classLocationRunnable = undefined
Java.perform(() => {
    classLocationRunnable = RegisterRunnable('xyz.chengzi.LocationRunnable', 'android.location.LocationListener', 'android.location.Location', function (listener, location) {
        listener.onLocationChanged(location)
    })
})

function setReplayLocationPassive(className, value) {
    const listener = locationListener[className]
    if (listener) {
        // listener.onLocationChanged(parseLocation(value))
        mainHandler.post(classLocationRunnable.$new(listener, parseLocation(value)))
    }
}

const sensorListener = {}

function replaySensorPassive(className) {
    instrument(className, 'onSensorChanged', function (event) {
        if (event.timestamp.value <= 0) {
            event.timestamp.value = SystemClock.elapsedRealtimeNanos()
            this.onSensorChanged(event)
        }
    });
}

function replaySensorPassiveAll() {
    instrumentOverload('android.hardware.SensorManager', 'registerListener', ['android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'], function (listener, sensor, period) {
        replaySensorPassive(listener.$className)
        sensorListener[listener.$className] = Java.retain(listener)
        return this.registerListener(listener, sensor, period)
    });
}

function replaySensor() {
    replaySensorPassiveAll()
}

const SensorEvent = Java.use('android.hardware.SensorEvent')

function parseSensorEvent(value) {
    const sensorEvent = SensorEvent.$new(value.values.length)
    sensorEvent.values.value = Java.array('float', value.values)
    sensorEvent.accuracy.value = value.accuracy
    sensorEvent.timestamp.value = -1
    return sensorEvent
}

let classSensorRunnable = undefined
Java.perform(() => {
    classSensorRunnable = RegisterRunnable('xyz.chengzi.SensorRunnable', 'android.hardware.SensorEventListener', 'android.hardware.SensorEvent', function (listener, event) {
        listener.onSensorChanged(event)
    })
})

function setReplaySensorPassive(className, value) {
    const listener = sensorListener[className]
    if (listener) {
        // listener.onSensorChanged(parseSensorEvent(value))
        mainHandler.post(classSensorRunnable.$new(listener, parseSensorEvent(value)))
    }
}

rpc.exports = {
    replayCollectViews,
    replayMotionEvent,
    replayKeyEvent,
    replayLocation,
    setReplayLocationActive,
    setReplayLocationPassive,
    replaySensor,
    setReplaySensorPassive
}
