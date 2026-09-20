import unittest
from darkvault.configuration import parse_scalar, encode_scalar, build_configuration


class ConfigurationTests(unittest.TestCase):
    def test_scalars_paths_and_conflicts(self):
        self.assertEqual(parse_scalar("00123"), "00123")
        self.assertEqual(parse_scalar("1e2", "number"), 100)
        self.assertIs(parse_scalar("false", "boolean"), False)
        self.assertIsNone(parse_scalar("null", "null"))
        for value in [float("nan"), float("inf"), 9007199254740992, {}, []]:
            with self.assertRaises(ValueError):
                encode_scalar(value)
        for value, kind in [("01", "number"), ("true", "number"), ("1", "boolean"), ("", "null")]:
            with self.assertRaises(ValueError):
                parse_scalar(value, kind)
        tree = build_configuration({"Redis:Port": 6379, "Redis:Enabled": False, "Literal\\:Key": "00123", "Empty": None, "Years:2026": "x"})
        self.assertEqual(tree["Redis"]["Port"], 6379)
        self.assertIs(tree["Redis"]["Enabled"], False)
        self.assertEqual(tree["Literal:Key"], "00123")
        self.assertIsNone(tree["Empty"])
        self.assertEqual(tree["Years"]["2026"], "x")
        for values in [{"A": "x", "A:B": 1}, {"A:B": 1, "A": None}, {"A::B": True}, {"A\\x": True}]:
            with self.assertRaises(ValueError):
                build_configuration(values)
        self.assertEqual(build_configuration({"A:B": 1, "A": 2}, False)["A:B"], 1)
