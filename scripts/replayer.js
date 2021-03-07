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
    replayLocationActive,
    replayLocationPassive,
    replaySensor
}
