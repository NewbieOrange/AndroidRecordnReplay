function record_touch(typename) {
    instrument(typename, 'dispatchTouchEvent', function (event) {
        send('Touch event intercepted: ' + event);
        return this.dispatchTouchEvent(event);
    });
}

function record_key(typename) {
    instrument(typename, 'dispatchKeyEvent', function (event) {
        send('Touch event intercepted: ' + event);
        return this.dispatchKeyEvent(event);
    });
}

function record_location() {
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        send('Location event intercepted: ' + location)
        return location
    });
}

function record() {
    record_touch('android.app.Activity');
    record_touch('android.app.Dialog');
    record_key('android.app.Activity');
    record_key('android.app.Dialog');
    record_location();
}

rpc.exports = {
    record
}
