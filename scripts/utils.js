const Class = Java.use("java.lang.Class")
const long = Class.getPrimitiveClass('long')
const int = Class.getPrimitiveClass('int')
const float = Class.getPrimitiveClass('float')
const Long = Java.use('java.lang.Long')
const Integer = Java.use('java.lang.Integer')
const Float = Java.use('java.lang.Float')
const Activity = Java.use('android.app.Activity')
const View = Java.use('android.view.View')
const ViewGroup = Java.use('android.view.ViewGroup')
const TextView = Java.use('android.widget.TextView')
const ContextWrapper = Java.use('android.content.ContextWrapper')

function instrumentOverload(typename, funcname, overload, impl) {
    Java.use(typename)[funcname].overload(...overload).implementation = impl;
}

function instrument(typename, funcname, impl) {
    Java.use(typename)[funcname].implementation = impl;
}

function getViewFullSignature(view) {
    let result = getViewActivity(view) + ';'
    // if (ViewGroup.class.isInstance(view)) {
    //     const viewGroup = Java.cast(view, ViewGroup)
    //     result += '('
    //     for (let i = 0; i < viewGroup.getChildCount(); i++) {
    //         result += getViewSignature(viewGroup.getChildAt(i)) + '/'
    //         if (ViewGroup.class.isInstance(viewGroup.getChildAt(i))) {
    //             const viewGroup2 = Java.cast(viewGroup.getChildAt(i), ViewGroup)
    //             result += '('
    //             for (let i = 0; i < viewGroup2.getChildCount(); i++) {
    //                 result += getViewSignature(viewGroup2.getChildAt(i)) + '/'
    //                 if (ViewGroup.class.isInstance(viewGroup2.getChildAt(i))) {
    //                     const viewGroup3 = Java.cast(viewGroup2.getChildAt(i), ViewGroup)
    //                     result += '('
    //                     for (let i = 0; i < viewGroup3.getChildCount(); i++) {
    //                         result += getViewSignature(viewGroup3.getChildAt(i)) + '/'
    //                     }
    //                     result += ')'
    //                 }
    //             }
    //             result += ')'
    //         }
    //     }
    //     result += ')'
    // }
    result += ';'
    for (let i = 0; view && i < 3; i++) {
        result += View.class.isInstance(view) ? getViewSignature(view) + '/' : '?'
        let viewParent = view.getParent()
        if (ViewGroup.class.isInstance(viewParent)) {
            const viewGroup = Java.cast(viewParent, ViewGroup)
            result += '('
            for (let i = 0; i < viewGroup.getChildCount(); i++) {
                const child = viewGroup.getChildAt(i)
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

function getViewSignature(view) {
    let extra = view.getTag() + ',' + view.getTooltipText() + ',' + view.getVisibility()
    // if (TextView.class.isInstance(view)) {
    //     extra = Java.cast(view, TextView).getText()
    // }
    return view.getId() + ',' + extra + '@' + view.getClass().getName()
}

function getViewActivity(view) {
    let context = view.getContext()
    while (ContextWrapper.class.isInstance(context)) {
        if (Activity.class.isInstance(context)) {
            const activity = Java.cast(context, Activity)
            return activity.getTitle()
        }
        context = Java.cast(context, ContextWrapper).getBaseContext()
    }
    return null
}

function isTopLevelDispatcher(view) {
    return !ViewGroup.class.isInstance(view.getParent())
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
