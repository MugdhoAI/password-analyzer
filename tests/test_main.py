"""
Tests for the password analyzer and generator.

Run with:
    python -m unittest discover tests
"""

import unittest

from src.analyzer import analyze_password, _detect_pool_size, _calculate_entropy
from src.generator import generate_password


class TestDetectPoolSize(unittest.TestCase):

    def test_lowercase_only(self):
        self.assertEqual(_detect_pool_size("abcdef"), 26)

    def test_lowercase_and_uppercase(self):
        self.assertEqual(_detect_pool_size("abcDEF"), 52)

    def test_all_four_classes(self):
        self.assertEqual(_detect_pool_size("aB3!"), 26 + 26 + 10 + 32)

    def test_empty_string_has_zero_pool(self):
        self.assertEqual(_detect_pool_size(""), 0)


class TestCalculateEntropy(unittest.TestCase):

    def test_longer_password_has_higher_entropy(self):
        short_entropy = _calculate_entropy("abc", 26)
        long_entropy = _calculate_entropy("abcdefgh", 26)
        self.assertGreater(long_entropy, short_entropy)

    def test_larger_pool_has_higher_entropy_at_same_length(self):
        small_pool_entropy = _calculate_entropy("abcdefgh", 26)
        large_pool_entropy = _calculate_entropy("abcdefgh", 94)
        self.assertGreater(large_pool_entropy, small_pool_entropy)

    def test_empty_password_has_zero_entropy(self):
        self.assertEqual(_calculate_entropy("", 26), 0.0)


class TestAnalyzePassword(unittest.TestCase):

    def test_common_password_is_flagged(self):
        result = analyze_password("password")
        self.assertTrue(result.is_common_password)
        self.assertEqual(result.strength_label, "Very Weak")

    def test_long_passphrase_scores_well_despite_no_symbols(self):
        # This is the key entropy-over-naive-rules demonstration:
        # a long, all-lowercase passphrase should still score strong.
        result = analyze_password("correcthorsebatterystaple")
        self.assertIn(result.strength_label, ["Strong", "Very Strong"])

    def test_short_password_is_weak(self):
        result = analyze_password("abc")
        self.assertEqual(result.strength_label, "Very Weak")

    def test_complex_short_password_beats_naive_expectations_correctly(self):
        # A short password with all character classes still shouldn't
        # be rated as strong as a long one — length dominates entropy.
        short_complex = analyze_password("Xy9!")
        long_simple = analyze_password("aaaaaaaaaaaaaaaa")
        self.assertGreater(long_simple.entropy_bits, short_complex.entropy_bits)

    def test_reasons_list_is_never_empty(self):
        result = analyze_password("Str0ng!Pass#word99")
        self.assertGreater(len(result.reasons), 0)


class TestGeneratePassword(unittest.TestCase):

    def test_generated_password_has_requested_length(self):
        password = generate_password(length=20)
        self.assertEqual(len(password), 20)

    def test_generated_password_contains_all_required_classes(self):
        password = generate_password(length=16)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))

    def test_no_symbols_flag_excludes_symbols(self):
        password = generate_password(length=16, use_symbols=False)
        self.assertTrue(all(c.isalnum() for c in password))

    def test_too_short_length_raises_error(self):
        with self.assertRaises(ValueError):
            generate_password(length=4)

    def test_generated_passwords_are_not_identical(self):
        # Sanity check that generation is actually randomized, not
        # accidentally deterministic.
        pw1 = generate_password(length=16)
        pw2 = generate_password(length=16)
        self.assertNotEqual(pw1, pw2)


if __name__ == "__main__":
    unittest.main()
