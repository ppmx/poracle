#!/usr/bin/env python3

class Interface:
    """ Defines the interface of the padding oracle. """

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
