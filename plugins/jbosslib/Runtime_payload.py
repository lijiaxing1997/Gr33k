import requests
import base64
import js2py

class Runtime_payload():

    @staticmethod
    def shell_encode(cmd):
        result = 'bash -c {echo,' + Runtime_payload.b64encode(cmd).decode() + '}|{base64,-d}|{bash,-i}'
        return result

    @staticmethod
    def b64encode(str):
        return base64.b64encode(str)
