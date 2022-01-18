class RSA():
    def __init__(self):

        # private keys:
        self.p = 0
        self.q = 0
        self.d = 0

        # public keys:
        self.n = self.p * self.q
        self.e = 0

    def __message_to_array(self, message):
        return list(map(ord, message))

    def __iterable_to_message(self, iterable):
        return "".join(map(chr, iterable))

    def __cypher_unicode_char(self, char):
        return char ** self.e % self.n

    def __decypher_unicode_char(self, char):
        return char ** self.d % self.n

    def cypher(self, message):
        message_arr = self.__message_to_array(message)
        *encrypted_message, = map(self.__cypher_unicode_char, message_arr)

        return encrypted_message

    def decypher(self, message_array):
        decrypted_message = map(self.__decypher_unicode_char, message_array)
        return self.__iterable_to_message(decrypted_message)
