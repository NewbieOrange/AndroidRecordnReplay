const earlyInstrument = true

function recordTouch(typename) {
    instrument(typename, 'onTouchEvent', function (event) {
        if (isTopLevelDispatcher(this)) {
            send(JSON.stringify({
                event: 'MotionEvent',
                downTime: event.getDownTime(),
                eventTime: event.getEventTime(),
                action: event.getActionMasked(),
                rawX: event.getRawX(),
                rawY: event.getRawY(),
                x: event.getX(),
                y: event.getY(),
                metaState: event.getMetaState(),
                view: getViewFullSignature(this)
            }))
        }
        return this.onTouchEvent(event);
    });
}

function recordTouchDispatch(typename) {
    instrument(typename, 'dispatchTouchEvent', function (event) {
        const dispatchedByView = this.dispatchTouchEvent(event)
        if (isTopLevelDispatcher(this)) {
            send(JSON.stringify({
                event: 'MotionEvent',
                downTime: event.getDownTime(),
                eventTime: event.getEventTime(),
                action: event.getActionMasked(),
                rawX: event.getRawX(),
                rawY: event.getRawY(),
                x: event.getX(),
                y: event.getY(),
                metaState: event.getMetaState(),
                view: getViewFullSignature(this)
            }))
        }
        return dispatchedByView;
    });
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
        return this.dispatchKeyEvent(event);
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
    recordTouch('android.view.View');
    recordKey('android.view.View');
    recordTouchDispatch('android.view.ViewGroup')
    recordKey('android.view.ViewGroup');
    recordLocation();
    recordSensorRegister();
    send('-- Record ready!');
}

rpc.exports = {
    record
}
