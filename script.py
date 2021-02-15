import frida

with open('utils.js', 'r') as f:
    utils = f.read()


def on_message(message, data):
    print(message)


class Script:
    def __init__(self, session: frida.core.Session, source):
        self.session = session
        self.script = session.create_script(utils + source)
        self.script.on('message', on_message)
        self.script.load()
        self.rpc = self.script.exports
