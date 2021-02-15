import frida

with open('utils.js', 'r') as f:
    utils = f.read()


class Script:
    def __init__(self, session: frida.core.Session, source: str):
        self.session = session
        self.script = session.create_script(utils + source)
        self.script.on('message', self.on_message)
        self.script.load()
        self.rpc = self.script.exports

    def on_message(self, message, data):
        print(message)
