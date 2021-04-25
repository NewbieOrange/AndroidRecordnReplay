const earlyInstrument = true

function sendMotionEvent(view, event) {
    send(JSON.stringify({
        event: 'MotionEvent',
        downTime: event.getDownTime(),
        eventTime: event.getEventTime(),
        action: event.getActionMasked(),
        rawX: event.getRawX(),
        rawY: event.getRawY(),
        x: event.getX(),
        y: event.getY(),
        pressure: event.getPressure(),
        size: event.getSize(),
        metaState: event.getMetaState(),
        xPrecision: event.getXPrecision(),
        yPrecision: event.getYPrecision(),
        deviceId: event.getDeviceId(),
        edgeFlags: event.getEdgeFlags(),
        view: getViewFullSignature(view),
        width: view.getWidth(),
        height: view.getHeight()
    }))
}

function sendKeyEvent(view, event) {
    send(JSON.stringify({
        event: 'KeyEvent',
        downTime: event.getDownTime(),
        eventTime: event.getEventTime(),
        action: event.getAction(),
        code: event.getKeyCode(),
        repeat: event.getRepeatCount(),
        metaState: event.getMetaState(),
        deviceId: event.getDeviceId(),
        scancode: event.getScanCode(),
        flags: event.getFlags(),
        source: event.getSource(),
        view: getViewFullSignature(view)
    }));
}

function sendLocationEvent(listener, provider, location) {
    const locationResult = {
        event: 'LocationEvent',
        provider: provider,
        longitude: location.getLongitude(),
        latitude: location.getLatitude(),
        bearing: location.getBearing(),
        speed: location.getSpeed(),
        altitude: location.getAltitude(),
        accuracy: location.getAccuracy(),
        listener: listener,
        eventTime: SystemClock.uptimeMillis()
    }
    send(JSON.stringify(locationResult))
}

let onTouchListeners = {}

function RegisterClassOnTouchListener() {
    return Java.registerClass({
        name: 'xyz.chengzi.OnTouchListener',
        implements: [Java.use('android.view.View$OnTouchListener')],
        methods: {
            onTouch: function (v, event) {
                const onTouchListener = onTouchListeners[v.hashCode()]
                sendMotionEvent(v, event)
                if (onTouchListener) {
                    return onTouchListener.onTouch(v, event)
                }
                return false
            }
        }
    })
}

let onTouchListenerStub = undefined

function recordTouch(typename) {
    instrumentOverload(typename, '$init', ['android.content.Context'], function (context) {
        this.setOnTouchListener(onTouchListenerStub)
        return this.$init(context)
    })
    instrument(typename, 'setOnTouchListener', function (listener) {
        if (!onTouchListenerStub.equals(listener)) {
            onTouchListeners[this.hashCode()] = Java.retain(listener)
        } else {
            this.setOnTouchListener(listener)
        }
    })
}

function recordKey(typename) {
    instrument(typename, 'dispatchKeyEvent', function (event) {
        if (isTopLevelDispatcher(this)) {
            sendKeyEvent(this, event)
        }
        return this.dispatchKeyEvent(event)
    });
}

function recordLocation() {
    // 1. instrument active location polling
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        sendLocationEvent('', provider, location)
        return location
    });
    // 2. instrument loaded passive location listeners
    if (!earlyInstrument) {
        const classLocationListener = Class.forName('android.location.LocationListener')
        Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
            onMatch(name, handle) {
                if (!name.startsWith('android.')) { // skip Android library classes
                    const classHandle = Java.cast(handle, Class)
                    if (classLocationListener.isAssignableFrom(classHandle)) {
                        recordLocationListener(name)
                    }
                }
            },
            onComplete() {
                send('-- Location instrumentation finished')
            }
        })
    }
    // 3. instrument future passive location listener
    instrumentOverload('android.location.LocationManager', 'requestLocationUpdates', ['java.lang.String', 'long', 'float', 'android.location.LocationListener'], function (provider, minTime, minDistance, listener) {
        recordLocationListener(listener.$className)
        return this.requestLocationUpdates(provider, minTime, minDistance, listener)
    });
}

function recordLocationListener(className) {
    instrumentOverload(className, 'onLocationChanged', ['android.location.Location'], function (location) {
        sendLocationEvent(className, '', location)
        return this.onLocationChanged(location)
    })
}

function recordSensorRegister() {
    if (!earlyInstrument) {
        const SensorEventListener = Class.forName('android.hardware.SensorEventListener')
        Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
            onMatch(name, handle) {
                if (!name.startsWith('android.')) { // skip Android library classes
                    const classHandle = Java.cast(handle, Class)
                    if (SensorEventListener.isAssignableFrom(classHandle)) {
                        recordSensorListener(name)
                    }
                }
            },
            onComplete() {
                send('-- Sensor instrumentation finished')
            }
        })
    }
    instrumentOverload('android.hardware.SensorManager', 'registerListener', ['android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'], function (listener, sensor, period) {
        recordSensorListener(listener.$className)
        return this.registerListener(listener, sensor, period)
    });
}

function recordSensorListener(className) {
    instrument(className, 'onSensorChanged', function (event) {
        const sensorEvent = {
            event: 'SensorEvent',
            values: event.values.value,
            sensor: event.sensor.value.getType(),
            accuracy: event.accuracy.value,
            timestamp: event.timestamp.value,
            listener: className,
            eventTime: SystemClock.uptimeMillis()
        }
        send(JSON.stringify(sensorEvent))
        return this.onSensorChanged(event)
    })
}

function record() {
    Java.perform(() => {
        const ClassOnTouchListener = RegisterClassOnTouchListener()
        onTouchListenerStub = ClassOnTouchListener.$new()
    })
    recordTouch('android.view.View')
    recordKey('android.view.View')
    recordKey('android.view.ViewGroup')
    recordLocation()
    recordSensorRegister()
    send('{"event":"TimeEvent","eventTime":"' + SystemClock.uptimeMillis() + '"}')
    send('-- Record ready!')
}

rpc.exports = {
    record
}
