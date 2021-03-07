function recordTouch(typename) {
    instrument(typename, 'dispatchTouchEvent', function (event) {
        send(event.toString());
        return this.dispatchTouchEvent(event);
    });
}

function recordKey(typename) {
    instrument(typename, 'dispatchKeyEvent', function (event) {
        send(event.toString());
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
    const classClass = Java.use('java.lang.Class')
    const classLocationListener = classClass.forName('android.location.LocationListener')
    Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
        onMatch(name, handle) {
            if (!name.startsWith('android.')) { // skip Android library classes
                const classHandle = Java.cast(handle, classClass)
                if (classLocationListener.isAssignableFrom(classHandle)) {
                    recordLocationListener(name)
                }
            }
        },
        onComplete() {
            send('-- Location instrumentation finished')
        }
    })
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
    const classClass = Java.use('java.lang.Class')
    const classSensorEventListener = classClass.forName('android.hardware.SensorEventListener')
    Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
        onMatch(name, handle) {
            if (!name.startsWith('android.')) { // skip Android library classes
                const classHandle = Java.cast(handle, classClass)
                if (classSensorEventListener.isAssignableFrom(classHandle)) {
                    recordSensorListener(name)
                }
            }
        },
        onComplete() {
            send('-- Sensor instrumentation finished')
        }
    })
    instrumentOverload('android.hardware.SensorManager', 'registerListener', ['android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'], function (listener, sensor, period) {
        recordSensorListener(listener.$className)
        return this.registerListener(listener, sensor, period)
    });
}

function recordSensorListener(className) {
    const classClass = Java.use('java.lang.Class')
    const classSensorEvent = classClass.forName('android.hardware.SensorEvent')
    const valuesField = classSensorEvent.getDeclaredField('values')
    const sensorField = classSensorEvent.getDeclaredField('sensor')
    const accuracyField = classSensorEvent.getDeclaredField('accuracy')
    const timestampField = classSensorEvent.getDeclaredField('timestamp')
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
    recordTouch('android.app.Activity');
    recordTouch('android.app.Dialog');
    recordKey('android.app.Activity');
    recordKey('android.app.Dialog');
    recordLocation();
    recordSensorRegister();
}

rpc.exports = {
    record
}
