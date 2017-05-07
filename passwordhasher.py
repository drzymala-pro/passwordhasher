# -*- coding: utf-8 -*-

import random
import string
import hashlib

MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 10


def is_password_secure(password):
    """
    Check if the password meets all of the secure password criteria:

    Password must meet at least 3 out of the following 4 complexity rules:
    at least 1 uppercase character (A-Z)
    at least 1 lowercase character (a-z)
    at least 1 digit (0-9)
    at least 1 special character (punctuation)

    Additionally:
    at least 10 characters
    at most 128 characters
    not more than 2 identical characters in a row (e.g., 111 not allowed)

    Note: do not forget to treat space as special characters too

    :param password: The password to be checked if it is secure.
    :return: True or False of whether the password does meet the secure password criteria.
    """
    good_length = MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH
    no_repeats = all((x != y != z for x, y, z in zip(password[:-2], password[1:-1], password[2:])))
    contains_digits = any((str.isdigit(x) for x in password))
    contains_special = any((not str.isalnum(x) for x in password))
    contains_lowercase = any((str.islower(x) for x in password))
    contains_uppercase = any((str.isupper(x) for x in password))

    return all([
        good_length,
        no_repeats,
        any([
            contains_uppercase and contains_lowercase and contains_digits,
            contains_uppercase and contains_lowercase and contains_special,
            contains_uppercase and contains_digits and contains_special,
            contains_lowercase and contains_digits and contains_special,
        ])
    ])


def create_random_password_salt():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(64))


def get_password_hash(password, salt):
    hash_object = hashlib.sha256()
    hash_object.update('<{0}:{1}:{2}>'.format(salt, password, '1').encode('utf-8'))
    return hash_object.hexdigest()


