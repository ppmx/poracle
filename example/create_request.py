#!/usr/bin/env python3

from base64 import urlsafe_b64encode as b64encode
from Crypto.Cipher import AES

def pkcs7_pad(data, length=16):
    pad = length - len(data) % length
    return data + bytes(pad * [pad])

def main():
    flag = b"The more you know, the more you realize you know nothing."
    key, iv = b"3452851383948128", b"8173648291826401"
    suite = AES.new(key, AES.MODE_CBC, iv)

    print("[+] using key:", key)
    print("[+] using iv:", iv)
    print("[+] using flag:", flag)

    print("[+] padded data:", pkcs7_pad(flag))

    data = iv + suite.encrypt(pkcs7_pad(flag))

    print("[+] query should be:")
    print("/search?data={0}".format(b64encode(data).decode()))

if __name__ == "__main__":
    main()
