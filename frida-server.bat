@echo off
set PATH=%PATH%;D:\android-sdk\platform-tools\
adb root
adb push "lib\frida-server" "/data/local/tmp/"
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "ps | grep frida-server | awk '{print $2}' | xargs kill -9"
adb shell "nohup /data/local/tmp/frida-server 2>/dev/null 1>/dev/null &"
