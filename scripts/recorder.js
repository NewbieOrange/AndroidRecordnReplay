function record_touch(typename) {
    instrument(typename, 'dispatchTouchEvent', function (event) {
        send(event.toString());
        return this.dispatchTouchEvent(event);
    });
}

function record_key(typename) {
    instrument(typename, 'dispatchKeyEvent', function (event) {
        send(event.toString());
        return this.dispatchKeyEvent(event);
    });
}

function record_location() {
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        send(location.toString())
        return location
    });
}

function record_sensor_register() {
    const classClass = Java.use('java.lang.Class')
    const classSensorEventListener = classClass.forName('android.hardware.SensorEventListener')
    Java.enumerateLoadedClasses({ // instrument already loaded (and probably registered) listeners
        onMatch(name, handle) {
            if (!name.startsWith('android.')) { // skip Android library classes
                const classHandle = Java.cast(handle, classClass)
                if (classSensorEventListener.isAssignableFrom(classHandle)) {
                    record_sensor_listener(name)
                }
            }
        },
        onComplete() {
            send('-- Sensor instrumentation finished')
        }
    })
    instrumentOverload('android.hardware.SensorManager', 'registerListener', ['android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int'], function (listener, sensor, period) {
        record_sensor_listener(listener.$className)
        return this.registerListener(listener, sensor, period)
    });
}

function record_sensor_listener(className) {
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
        send('SensorEvent ' + JSON.stringify(sensorEvent))
        return this.onSensorChanged(event)
    })
}

function record() {
    record_touch('android.app.Activity');
    record_touch('android.app.Dialog');
    record_key('android.app.Activity');
    record_key('android.app.Dialog');
    record_location();
    record_sensor_register();
}

rpc.exports = {
    record
}
