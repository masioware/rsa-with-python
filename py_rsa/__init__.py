class RSA():
    def __init__(self):

        # private keys:
        self.p = 0
        self.q = 0
        self.d = 0

        # public keys:
        self.n = 0
        self.e = 0

    def set_private_keys(self, p_key, q_key, d_key):
        self.p, self.q, self.d = p_key, q_key, d_key

    def set_public_keys(self, n_key, e_key):
        self.n, self.e = n_key, e_key

    def __message_to_array(self, message):
        return list(map(ord, message))

    def __iterable_to_message(self, iterable):
        return "".join(map(chr, iterable))

    def __cipher_unicode_char(self, char):
        return char ** self.e % self.n

    def __decipher_unicode_char(self, char):
        return char ** self.d % self.n

    def cipher(self, message):
        message_arr = self.__message_to_array(message)
        *encrypted_message, = map(self.__cipher_unicode_char, message_arr)

        return encrypted_message

    def decipher(self, message_array):
        decrypted_message = map(self.__decipher_unicode_char, message_array)
        return self.__iterable_to_message(decrypted_message)
