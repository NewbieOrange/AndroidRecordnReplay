const Class = Java.use("java.lang.Class");
const long = Class.getPrimitiveClass('long');
const int = Class.getPrimitiveClass('int');
const float = Class.getPrimitiveClass('float');
const Long = Java.use('java.lang.Long')
const Integer = Java.use('java.lang.Integer')
const Float = Java.use('java.lang.Float')

function instrumentOverload(typename, funcname, overload, impl) {
    Java.perform(() => {
        const type = Java.use(typename);
        type[funcname].overload(...overload).implementation = impl;
    })
}

function instrument(typename, funcname, impl) {
    Java.perform(() => {
        const type = Java.use(typename);
        type[funcname].implementation = impl;
    })
}

function getViewFullSignature(view) {
    const ViewGroup = Java.use('android.view.ViewGroup')
    const ViewGroupHandle = Class.forName('android.view.ViewGroup')
    let result = ''
    for (let i = 0; i < 5; i++) {
        if (view !== null) {
            result += getViewSignature(view) + '/'
            let viewParent = view.getParent()
            if (ViewGroupHandle.isInstance(viewParent)) {
                view = Java.cast(viewParent, ViewGroup)
            } else {
                view = null
            }
        } else {
            result += 'null/'
        }
    }
    return result
}

function getViewSignature(view) {
    const TextView = Java.use('android.widget.TextView')
    let extra = ''
    if (TextView.class.isInstance(view)) {
        extra = Java.cast(view, TextView).getText()
    }
    return view.getId() + ',' + extra + '@' + view.getClass().getName()
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
