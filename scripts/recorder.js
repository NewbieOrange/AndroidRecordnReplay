const earlyInstrument = true

function sendMotionEvent(view, event) {
    sendBuffered(JSON.stringify({
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
    sendBuffered(JSON.stringify({
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
    let locationResult
    if (location) {
        locationResult = {
            event: 'LocationEvent',
            provider: provider,
            longitude: location.getLongitude(),
            latitude: location.getLatitude(),
            bearing: location.getBearing(),
            speed: location.getSpeed(),
            altitude: location.getAltitude(),
            accuracy: location.getAccuracy(),
            listener: listener,
            eventTime: SystemClock.uptimeMillis(),
            nullInput: false
        }
    } else {
        locationResult = {
            event: 'LocationEvent',
            provider: provider,
            listener: listener,
            eventTime: SystemClock.uptimeMillis(),
            nullInput: true
        }
    }
    sendBuffered(JSON.stringify(locationResult))
}

function sendSensorEvent(listener, event) {
    const sensorEvent = {
        event: 'SensorEvent',
        values: event.values.value,
        sensor: event.sensor.value.getType(),
        accuracy: event.accuracy.value,
        timestamp: event.timestamp.value,
        listener: listener,
        eventTime: SystemClock.uptimeMillis()
    }
    sendBuffered(JSON.stringify(sensorEvent))
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
    Java.perform(() => {
        const ClassOnTouchListener = RegisterClassOnTouchListener()
        onTouchListenerStub = ClassOnTouchListener.$new()
        instrumentOverload(typename, '$init', ['android.content.Context'], function (context) {
            if (!this.$className.startsWith('com.google.vr.sdk')) {
                this.setOnTouchListener(onTouchListenerStub)
            }
            return this.$init(context)
        })
    })
    instrument(typename, 'setOnTouchListener', function (listener) {
        if (listener && !onTouchListenerStub.equals(listener)) {
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

let ClassLocationListenerStub = undefined
const locationListenerStubs = {}

function RegisterClassLocationListener() {
    return Java.registerClass({
        name: 'xyz.chengzi.LocationListener',
        implements: [Java.use('android.location.LocationListener')],
        fields: {
            className: 'java.lang.String'
        },
        methods: {
            $init: {
                argumentTypes: ['java.lang.String'],
                implementation(className) {
                    this.className.value = className
                }
            },
            onLocationChanged: function (location) {
                sendLocationEvent(this.className.value, '', location)
            },
            onStatusChanged: function (provider, status, extras) {
            },
            onProviderEnabled: function (provider) {
            },
            onProviderDisabled: function (provider) {
            }
        }
    })
}

function recordLocation() {
    Java.perform(() => {
        ClassLocationListenerStub = RegisterClassLocationListener()

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
            // recordLocationListener(listener.$className)
            if (locationListenerStubs[listener.$className]) {
                const stub = ClassLocationListenerStub.$new(listener.$className)
                locationListenerStubs[listener.$className] = stub
                this.requestLocationUpdates(provider, minTime, minDistance, stub)
            }
            return this.requestLocationUpdates(provider, minTime, minDistance, listener)
        });
        instrumentOverload('android.location.LocationManager', 'removeUpdates', ['android.location.LocationListener'], function (listener) {
            const stub = locationListenerStubs[listener.$className]
            if (stub) {
                delete locationListenerStubs[listener.$className]
                this.removeUpdates(stub)
            }
            return this.removeUpdates(listener)
        });
    })
}

function recordLocationListener(className) {
    instrumentOverload(className, 'onLocationChanged', ['android.location.Location'], function (location) {
        sendLocationEvent(className, '', location)
        return this.onLocationChanged(location)
    })
}

let ClassSensorEventListenerStub = undefined
const sensorEventListenerStubs = {}

function RegisterClassSensorEventListener() {
    return Java.registerClass({
        name: 'xyz.chengzi.SensorEventListener',
        implements: [Java.use('android.hardware.SensorEventListener')],
        fields: {
            className: 'java.lang.String'
        },
        methods: {
            $init: {
                argumentTypes: ['java.lang.String'],
                implementation(className) {
                    this.className.value = className
                }
            },
            onSensorChanged: function (event) {
                sendSensorEvent(this.className.value, event)
            },
            onAccuracyChanged: function (sensor, accuracy) {
            }
        }
    })
}

function recordSensor() {
    Java.perform(() => {
        ClassSensorEventListenerStub = RegisterClassSensorEventListener()

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
            // recordSensorListener(listener.$className)
            if (!sensorEventListenerStubs[listener.$className]) {
                const stub = ClassSensorEventListenerStub.$new(listener.$className)
                sensorEventListenerStubs[listener.$className] = stub
                this.registerListener(stub, sensor, period)
            }
            return this.registerListener(listener, sensor, period)
        });
        instrumentOverload('android.hardware.SensorManager', 'unregisterListener', ['android.hardware.SensorEventListener'], function (listener) {
            const stub = sensorEventListenerStubs[listener.$className]
            if (stub) {
                delete sensorEventListenerStubs[listener.$className]
                this.unregisterListener(stub)
            }
            return this.unregisterListener(listener)
        });
    })
}

function recordSensorListener(className) {
    instrument(className, 'onSensorChanged', function (event) {
        sendSensorEvent(className, event)
        return this.onSensorChanged(event)
    })
}

function recordTouchAndKey() {
    recordTouch('android.view.View')
    recordKey('android.view.View')
    recordKey('android.view.ViewGroup')
}

// Call this function after all other `record` functions
function recordTimeSync() {
    send('{"event":"TimeEvent","eventTime":"' + SystemClock.uptimeMillis() + '"}')
    send('-- Record ready!')
}

rpc.exports = {
    recordTouchAndKey,
    recordLocation,
    recordSensor,
    recordTimeSync,
    flushBuffer
}
