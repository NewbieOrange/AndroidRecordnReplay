function instrument(typename, funcname, impl) {
    Java.perform(() => {
        const type = Java.use(typename);
        type[funcname].implementation = impl;
    })
}
