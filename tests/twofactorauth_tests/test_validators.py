from django.contrib.twofactorauth.validators import hex_validator
from django.core.exceptions import ValidationError
from django.test import TestCase


class HexValidatorTest(TestCase):
    def test_zero_length(self):
        self.assertIsNone(hex_validator()('0123456789abcdef'))

    def test_non_zero_length(self):
        self.assertIsNone(hex_validator(8)('0123456789abcdef'))

    def test_byte_string(self):
        self.assertIsNone(hex_validator(8)(b'0123456789abcdef'))

    def test_non_hex_string(self):
        test_string = 'test'
        expected_error = "b'%s' is not valid hex-encoded data." % test_string

        with self.assertRaises(ValidationError) as cm:
            hex_validator()(test_string)
        self.assertEqual(cm.exception.messages, [expected_error])

    def test_wrong_length_string(self):
        test_string = '0123456789abcdef'
        expected_error = "b'{0}' does not represent exactly {1} bytes."

        with self.assertRaises(ValidationError) as cm:
            hex_validator(7)(test_string)
        self.assertEqual(cm.exception.messages, [expected_error.format(test_string, 7)])

        with self.assertRaises(ValidationError) as cm:
            hex_validator(9)(test_string)
        self.assertEqual(cm.exception.messages, [expected_error.format(test_string, 9)])
