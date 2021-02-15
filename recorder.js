function record() {
    instrument('android.app.Activity', 'dispatchTouchEvent', function (event) {
        send('Touch event intercepted: ' + event)
        return this.dispatchTouchEvent(event)
    });
    instrument('android.app.Activity', 'dispatchKeyEvent', function (event) {
        send('Key event intercepted: ' + event)
        return this.dispatchKeyEvent(event)
    });
}

rpc.exports = {
    record
}
