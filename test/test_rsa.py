from py_rsa import RSA


def test_public_keys_are_setted():
    r = RSA()
    r.set_public_keys(391, 3)

    assert r.n == 391
    assert r.e == 3


def test_private_keys_are_setted():
    r = RSA()
    r.set_private_keys(17, 23, 235)

    assert r.p == 17
    assert r.q == 23
    assert r.d == 235


def test_message_to_array():
    r = RSA()

    array = r._RSA__message_to_array("abcdef")
    assert array == [97, 98, 99, 100, 101, 102]


def test_iterable_to_message():
    r = RSA()

    message = r._RSA__iterable_to_message([97, 98, 99, 100, 101, 102])
    assert message == "abcdef"


def test_cypher_unicode_char():
    r = RSA()
    r.set_public_keys(391, 3)

    char_1 = r._RSA__cypher_unicode_char(97)
    char_2 = r._RSA__cypher_unicode_char(98)
    char_3 = r._RSA__cypher_unicode_char(99)
    char_4 = r._RSA__cypher_unicode_char(100)

    assert char_1 == 79
    assert char_2 == 55
    assert char_3 == 228
    assert char_4 == 213


def test_decypher_unicode_char():
    r = RSA()

    r.d = 235
    r.n = 391

    char_1 = r._RSA__decypher_unicode_char(79)
    char_2 = r._RSA__decypher_unicode_char(55)
    char_3 = r._RSA__decypher_unicode_char(228)
    char_4 = r._RSA__decypher_unicode_char(213)

    assert char_1 == 97
    assert char_2 == 98
    assert char_3 == 99
    assert char_4 == 100


def test_cypher_message():
    r = RSA()
    r.set_public_keys(391, 3)

    encrypted_message_1 = r.cypher("test")
    encrypted_message_2 = r.cypher("message")

    assert encrypted_message_1 == [24, 16, 276, 24]
    assert encrypted_message_2 == [37, 16, 276, 276, 79, 273, 16]


def test_decypher_message():
    r = RSA()

    r.d = 235
    r.n = 391

    encrypted_message_1 = [24, 16, 276, 24]
    message_1 = r.decypher(encrypted_message_1)

    encrypted_message_2 = [37, 16, 276, 276, 79, 273, 16]
    message_2 = r.decypher(encrypted_message_2)

    assert message_1 == "test"
    assert message_2 == "message"
