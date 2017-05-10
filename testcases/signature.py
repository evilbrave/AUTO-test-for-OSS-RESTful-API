import OpenSSL
from OpenSSL import crypto
import base64
import os
import inspect
import common_data


class Signature:
    #def __init__(self):
        #print "init signature"

    def load_key(self, serial_number):
        pkey_path = os.path.dirname(os.path.abspath(inspect.stack()[0][1]))
        if serial_number == "1002":
            keyfile = pkey_path + "/keys/pkey1002.pem"
            #print "load key...: " + keyfile

        elif serial_number == "1005":
            keyfile = pkey_path + "/keys/pkey1005.pem"
            #print "load key...: " + keyfile

        elif serial_number == "1004":
            keyfile = pkey_path + "/keys/pkey1004.pem"
            #print "load key...: " + keyfile
        else:
            print "unknown certificate number"
            exit(-1)

        key_file = open(keyfile, "r")
        key = key_file.read()
        key_file.close()

        if key.startswith('-----BEGIN '):
            self.pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        else:
            self.pkey = crypto.load_pkcs12(key).get_privatekey()

    def sign(self, text):
        sign = OpenSSL.crypto.sign(self.pkey, text, "sha224")

        data_base64 = base64.b64encode(sign)
        return data_base64


if __name__ == '__main__':
    # text = "3464fcbf4dcf00a4ac6ffc2ab384da2402f6af9082d421474c629a20e20469711002zD-dXV5RcYE0zI4z9SgsKqA5CF4AB5C74B8S140Z46002315"
    text = "Test"
    signature = Signature()
    signature.load_key(common_data.certificate_serial)
    sign = signature.sign(text)
    print sign
