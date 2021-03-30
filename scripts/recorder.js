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

let onTouchListeners = {}
let instrumentedViews = {}

function RegisterClassOnTouchListener() {
    return Java.registerClass({
        name: 'xyz.chengzi.OnTouchListener',
        implements: [Java.use('android.view.View$OnTouchListener')],
        fields: {
            view: 'android.view.View'
        },
        methods: {
            onTouch: function (v, event) {
                const onTouchListener = onTouchListeners[v.hashCode()]
                if (onTouchListener) {
                    return onTouchListener.onTouch(v, event)
                } else {
                    sendMotionEvent(v, event)
                    return false
                }
            }
        }
    })
}

let onTouchListenerStub = undefined

function recordTouch(typename) {
    // instrument(typename, 'onTouchEvent', function (event) {
    //     sendMotionEvent(this, event)
    //     return this.onTouchEvent(event)
    // })
    instrument('android.view.View', 'setOnTouchListener', function (listener) {
        if (!onTouchListenerStub.equals(listener)) {
            onTouchListeners[this.hashCode()] = Java.retain(listener)
        } else {
            this.setOnTouchListener(listener)
        }
    })
    instrumentOverload('android.view.View', 'onDraw', ['android.graphics.Canvas'], function (canvas) {
        this.onDraw(canvas)
        if (!instrumentedViews[this.hashCode()]) {
            this.setOnTouchListener(onTouchListenerStub)
        } else {
            instrumentedViews[this.hashCode()] = true
        }
    })
    instrumentOverload('android.view.View', 'draw', ['android.graphics.Canvas'], function (canvas) {
        this.draw(canvas)
        if (!instrumentedViews[this.hashCode()]) {
            this.setOnTouchListener(onTouchListenerStub)
        } else {
            instrumentedViews[this.hashCode()] = true
        }
    })
}

function recordKey(typename) {
    instrument(typename, 'dispatchKeyEvent', function (event) {
        if (isTopLevelDispatcher(this)) {
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
                view: getViewFullSignature(this)
            }));
        }
        return this.dispatchKeyEvent(event)
    });
}

function recordLocation() {
    // 1. instrument active location polling
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        send(location.toString())
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
    instrument(className, 'onLocationChanged', function (location) {
        const locationResult = {
            longitude: location.getLongitude(),
            latitude: location.getLatitude(),
            bearing: location.getBearing(),
            speed: location.getSpeed(),
            altitude: location.getAltitude(),
            accuracy: location.getAccuracy(),
            listener: className
        }
        send('LocationResult ' + JSON.stringify(locationResult))
        return this.onLocationChanged(location)
    })
}

function recordSensorRegister() {
    if (!earlyInstrument) {
        const SensorEventListener = Java.use('android.hardware.SensorEventListener')
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
    const SensorEvent = Java.use('android.hardware.SensorEvent')
    const valuesField = SensorEvent.getDeclaredField('values')
    const sensorField = SensorEvent.getDeclaredField('sensor')
    const accuracyField = SensorEvent.getDeclaredField('accuracy')
    const timestampField = SensorEvent.getDeclaredField('timestamp')
    instrument(className, 'onSensorChanged', function (event) {
        const sensorEvent = Object()
        sensorEvent.values = javaArrayToString(Java.array('float', valuesField.get(event)))
        sensorEvent.sensor = sensorField.get(event).toString()
        sensorEvent.accuracy = accuracyField.get(event).toString()
        sensorEvent.timestamp = timestampField.get(event).toString()
        sensorEvent.listener = className
        send('SensorEvent ' + JSON.stringify(sensorEvent))
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
    send('-- Record ready!')
}

rpc.exports = {
    record
}
