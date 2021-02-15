function record() {
    instrument('android.app.Activity', 'dispatchTouchEvent', function (event) {
        send('Touch event intercepted: ' + event)
        return this.dispatchTouchEvent(event)
    });
    instrument('android.app.Activity', 'dispatchKeyEvent', function (event) {
        send('Key event intercepted: ' + event)
        return this.dispatchKeyEvent(event)
    });
    instrument('android.location.LocationManager', 'getLastKnownLocation', function (provider) {
        const location = this.getLastKnownLocation(provider)
        send('Location event intercepted: ' + location)
        return location
    });
}

rpc.exports = {
    record
}
