from django.contrib.twofactorauth.key_generation import random_hex
from django.contrib.twofactorauth.validators import hex_validator
from django.test import TestCase


class KeyGeneratorTest(TestCase):
    def test_random_hex(self):
        self.assertIsNone(hex_validator()(random_hex()))
        self.assertIsNone(hex_validator()(random_hex(10)))
