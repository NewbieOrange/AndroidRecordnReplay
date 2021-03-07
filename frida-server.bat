@echo off
set PATH=%PATH%;D:\android-sdk\platform-tools\
adb push "lib\frida-server" "/data/local/tmp/"
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
