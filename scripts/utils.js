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
