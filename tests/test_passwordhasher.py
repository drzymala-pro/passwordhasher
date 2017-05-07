# -*- coding: utf-8 -*-

import unittest
from passwordhasher import is_password_secure, create_random_password_salt, get_password_hash


class TestIsPasswordSecure(unittest.TestCase):
    """
    Password must meet at least 3 out of the following 4 complexity rules:
    at least 1 uppercase character (A-Z)
    at least 1 lowercase character (a-z)
    at least 1 digit (0-9)
    at least 1 special character (punctuation) - do not forget
        to treat space as special characters too

    Additionally:
    at least 10 characters
    at most 128 characters
    not more than 2 identical characters in a row (e.g., 111 not allowed)

    Please note:
    Function may return True or False. No other outcome is allowed.
    It should be impossible to guess why a password is not strong.
    """
    secure_password = '123$abc #&'

    def test_check_if_function_does_not_tell_too_much(self):
        result = is_password_secure(self.secure_password)
        self.assertTrue(result is True or result is False, 'Function may return True or False. NOTHING ELSE!')

    def test_secure_password_should_pass(self):
        secure = is_password_secure(self.secure_password)
        self.assertTrue(secure, 'Secure password should be secure')

    def test_password_longer_than_128_should_fail(self):
        a128longstring = 'abcd' * 32
        good = (self.secure_password + a128longstring)[:128]
        baad = good + 'a'
        good_is_good = is_password_secure(good)
        baad_is_good = is_password_secure(baad)
        self.assertTrue(good_is_good, '128 characters long password should be valid')
        self.assertFalse(baad_is_good, 'Over 128 characters long password should not be valid')

    def test_password_shorter_than_10_should_fail(self):
        short_pass = self.secure_password[:9]
        secure = is_password_secure(short_pass)
        self.assertFalse(secure, 'Nine chars long password should not be valid')

    def test_password_with_3_identical_chars_in_row_should_fail(self):
        password = self.secure_password + 'kkk'
        secure = is_password_secure(password)
        self.assertFalse(secure, 'Password with three identical chars in row should be insecure')

    def test_password_without_numbers_or_special_chars_should_fail(self):
        password = 'abcdefgHIJKLMNOP'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without numbers or special chars must be insecure.')

    def test_password_without_lowercase_or_special_chars_should_fail(self):
        password = 'ABCDEFGHIJKLMNOP123'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without lowercase or special chars should be insecure.')

    def test_password_without_lowercase_or_digits_should_fail(self):
        password = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without lowercase or number chars should be insecure.')

    def test_password_without_uppercase_or_special_chars_must_fail(self):
        password = 'abcdefghijklmnopqrstuvw1235'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without uppercase or special characters should be insecure.')

    def test_password_without_uppercase_or_digits_must_fail(self):
        password = 'abcdefghijklmnopqrstuv!@#$'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without uppercase or number characters should be insecure.')

    def test_password_without_characters_should_fail(self):
        password = '123456789-!@#$%^'
        result = is_password_secure(password)
        self.assertFalse(result, 'Password without any characters should be insecure.')

    def test_spacebar_is_treated_as_special_character(self):
        password = 'ABCDE abcde'
        result = is_password_secure(password)
        self.assertTrue(result, 'Spacebar should be treated as special character.')


class TestCreateRandomPasswordSatl(unittest.TestCase):

    def test_if_generated_salt_is_random(self):
        salts = [create_random_password_salt() for x in range(1000)]
        unique_salts = set(salts)
        result = len(salts) == len(unique_salts)
        self.assertTrue(result, 'Created password salts should be random.')


class TestGetPasswordHash(unittest.TestCase):

    def test_same_salt_and_password_returns_same_hash(self):
        salt = 'aaaa'
        password = 'bbbb'
        hash1 = get_password_hash(salt, password)
        hash2 = get_password_hash(salt, password)
        self.assertEqual(hash1, hash2, 'Same salt and password should return same hash')

    def test_different_salt_and_same_password_returns_different_hash(self):
        password = 'aaaa'
        salt1 = 'bbbb'
        hash1 = get_password_hash(salt1, password)
        salt2 = 'cccc'
        hash2 = get_password_hash(salt2, password)
        self.assertNotEqual(hash1, hash2, 'Different salt and same password should return different hash')

    def test_same_salt_and_different_password_returns_different_hash(self):
        salt = 'aaaa'
        password1 = 'bbbb'
        hash1 = get_password_hash(salt, password1)
        password2 = 'cccc'
        hash2 = get_password_hash(salt, password2)
        self.assertNotEqual(hash1, hash2, 'Different salt and same password should return different hash')

