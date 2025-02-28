const Class = Java.use("java.lang.Class")
const long = Class.getPrimitiveClass('long')
const int = Class.getPrimitiveClass('int')
const float = Class.getPrimitiveClass('float')
const Long = Java.use('java.lang.Long')
const Integer = Java.use('java.lang.Integer')
const Float = Java.use('java.lang.Float')
const Runnable = Java.use('java.lang.Runnable')
const Activity = Java.use('android.app.Activity')
const View = Java.use('android.view.View')
const ViewGroup = Java.use('android.view.ViewGroup')
const TextView = Java.use('android.widget.TextView')
const ContextWrapper = Java.use('android.content.ContextWrapper')
const SystemClock = Java.use('android.os.SystemClock')
const Handler = Java.use('android.os.Handler')
const Looper = Java.use('android.os.Looper')

let mainHandler = undefined
Java.perform(() => {
    mainHandler = Handler.$new(Looper.getMainLooper())
})

function RegisterRunnable(className, arg1Type, arg2Type, func) {
    return Java.registerClass({
        name: className,
        implements: [Runnable],
        fields: {
            arg1: arg1Type,
            arg2: arg2Type
        },
        methods: {
            $init: {
                argumentTypes: [arg1Type, arg2Type],
                implementation(arg1, arg2) {
                    this.arg1.value = arg1
                    this.arg2.value = arg2
                }
            },
            run: function () {
                func(this.arg1.value, this.arg2.value)
            }
        }
    })
}

function instrumentOverload(typename, funcname, overload, impl) {
    Java.use(typename)[funcname].overload(...overload).implementation = impl;
}

function instrument(typename, funcname, impl) {
    Java.use(typename)[funcname].implementation = impl;
}

function getViewChildSignature(view, depth) {
    if (depth === 0 || !ViewGroup.class.isInstance(view)) {
        return getViewSignature(view)
    } else {
        const viewGroup = Java.cast(view, ViewGroup)
        let result = getViewSignature(view) + '('
        for (let i = 0; i < viewGroup.getChildCount(); i++) {
            result += getViewChildSignature(viewGroup.getChildAt(i), depth - 1) + '/'
        }
        return result + ')'
    }
}

function getViewParentSignature(view, depth) {
    let result = ''
    for (let i = 0; view && i < depth; i++) {
        result += View.class.isInstance(view) ? getViewSignature(view) + '/' : '?/'
        let viewParent = view.getParent()
        if (ViewGroup.class.isInstance(viewParent)) {
            const viewGroup = Java.cast(viewParent, ViewGroup)
            result += '('
            for (let j = 0; j < viewGroup.getChildCount(); j++) {
                const child = viewGroup.getChildAt(j)
                if (view.equals(child)) {
                    result += './'
                } else {
                    result += getViewSignature(child) + '/'
                }
            }
            view = viewGroup
            result += ')/'
        } else {
            view = viewParent
        }
    }
    return result
}

function getViewFullSignature(view) {
    // let result = ''
    // const activity = getViewActivity(view)
    // if (activity) {
    //     result += activity.getTitle()
    // }
    return getViewSignature(view) + '$' + getViewChildSignature(view, 1) + '+' + getViewParentSignature(view, 3)
}

function getViewSignature(view) {
    let extra = ''
    // if (TextView.class.isInstance(view)) {
    //     extra += ',' + Java.cast(view, TextView).getText()
    // }
    return view.getId() + '#' + extra + '@' + view.$className
}

function getViewActivity(view) {
    let context = view.getContext()
    while (ContextWrapper.class.isInstance(context)) {
        if (Activity.class.isInstance(context)) {
            return Java.cast(context, Activity)
        }
        context = Java.cast(context, ContextWrapper).getBaseContext()
    }
    return null
}

function isTopLevelDispatcher(view) {
    return !ViewGroup.class.isInstance(view.getParent())
}

function isLastLevelDispatcher(viewGroup) {
    for (let i = 0; i < viewGroup.getChildCount(); i++) {
        if (ViewGroup.class.isInstance(viewGroup.getChildAt(i))) {
            return false
        }
    }
    return true
}

function adjustCoordinates(view, x, y, originalWidth, originalHeight) {
    return {
        x: x * view.getWidth() / originalWidth,
        y: y * view.getHeight() / originalHeight
    }
}

function insert(string, index, value) {
    return string.substr(0, index) + value + string.substr(index);
}

function replaceAt(string, index, replacement) {
    return string.substr(0, index) + replacement + string.substr(index + replacement.length);
}

function javaArrayToString(array) {
    let string = '['
    for (let i = 0; i < array.length; i += 1) {
        string += array[i] + ','
    }
    return replaceAt(string, string.length - 1, ']')
}

function dumpJavaObject(object) {
    let jsObject = Object()
    object.class.getFields().forEach(function (it) {
        jsObject[it.getName()] = it.get(object).toString()
    })
    return jsObject
}

let messageBuffer = ''

function sendBuffered(message) {
    messageBuffer += message + '\n'
    if (messageBuffer.length > 1024) {
        send(messageBuffer)
        messageBuffer = ''
    }
}

function flushBuffer() {
    send(messageBuffer)
}
