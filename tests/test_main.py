"""
Tests for the password analyzer and generator.

Run with:
    python -m unittest discover tests
"""

import math
import unittest

from src.analyzer import (
    analyze_password,
    estimate_crack_time_seconds,
    format_crack_time,
    _detect_pool_size,
    _calculate_entropy,
)
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


class TestCrackTime(unittest.TestCase):

    def test_zero_entropy_cracks_instantly(self):
        self.assertEqual(estimate_crack_time_seconds(0), 0.0)

    def test_higher_entropy_takes_longer_to_crack(self):
        weak = estimate_crack_time_seconds(30)
        strong = estimate_crack_time_seconds(70)
        self.assertGreater(strong, weak)

    def test_format_subsecond(self):
        self.assertEqual(format_crack_time(0.4), "less than a second")

    def test_format_seconds_and_minutes(self):
        self.assertEqual(format_crack_time(45), "45 seconds")
        self.assertEqual(format_crack_time(600), "10 minutes")

    def test_format_hours_and_days(self):
        self.assertEqual(format_crack_time(7200), "2 hours")
        self.assertEqual(format_crack_time(432000), "5 days")

    def test_format_years_and_beyond(self):
        self.assertEqual(format_crack_time(31_536_000 * 120), "120 years")
        self.assertIn("thousand years", format_crack_time(31_536_000 * 4500))
        self.assertEqual(
            format_crack_time(31_536_000 * 2_000_000_000_000),
            "over a trillion years",
        )

    def test_analysis_reports_crack_time(self):
        result = analyze_password("correcthorsebatterystaple")
        self.assertGreater(result.crack_time_seconds, 0)
        self.assertEqual(result.crack_time_display, "over a trillion years")

    def test_common_password_crack_time_is_instant(self):
        result = analyze_password("password")
        self.assertEqual(result.crack_time_seconds, 0.0)
        self.assertTrue(result.crack_time_display.startswith("instantly"))

    def test_huge_entropy_returns_infinite_crack_time(self):
        # Regression test: past roughly 1024 bits of entropy the raw
        # 2 ** entropy calculation overflows a float and raises
        # OverflowError instead of returning a number.
        self.assertEqual(estimate_crack_time_seconds(2000), math.inf)
        self.assertEqual(format_crack_time(math.inf), "over a trillion years")

    def test_very_long_password_does_not_crash(self):
        result = analyze_password("Aa1!" * 50)  # 200 characters
        self.assertEqual(result.strength_label, "Very Strong")
        self.assertEqual(result.crack_time_seconds, math.inf)
        self.assertEqual(result.crack_time_display, "over a trillion years")


class TestPatternDetection(unittest.TestCase):

    def test_repeated_characters_are_flagged(self):
        result = analyze_password("Mypaaassword1!")
        self.assertTrue(any("in a row" in r for r in result.reasons))

    def test_repeated_run_reports_its_full_length(self):
        # Regression test: the old scan stopped counting at 3, so a
        # five character run was reported as only three repeats.
        result = analyze_password("Mypaaaaassword1!")
        self.assertTrue(any("5 times in a row" in r for r in result.reasons))

    def test_two_repeats_are_not_flagged(self):
        result = analyze_password("Moonlight7!Trail")
        self.assertFalse(any("in a row" in r for r in result.reasons))

    def test_letter_sequence_is_flagged(self):
        result = analyze_password("myabcPass9!word")
        self.assertTrue(any("sequence" in r for r in result.reasons))

    def test_descending_and_digit_sequences_are_flagged(self):
        self.assertTrue(any(
            "sequence" in r for r in analyze_password("Zyx9!strongpass").reasons
        ))
        self.assertTrue(any(
            "sequence" in r for r in analyze_password("pass321Word!x").reasons
        ))

    def test_clean_password_has_no_pattern_reasons(self):
        result = analyze_password("Tr7!kQ9#mZ2&wP")
        self.assertFalse(any("sequence" in r for r in result.reasons))
        self.assertFalse(any("in a row" in r for r in result.reasons))


if __name__ == "__main__":
    unittest.main()
