from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import open_studentaid
from open_studentaid.api import _loan_list, _loan_total, _money
from open_studentaid.openstudentaid import (
    _method_pattern,
    _redact,
    _resolve_mfa_code,
    save_session as save_core_session,
)
from open_studentaid.config import LAST_SESSION_STATES


MODELS = json.loads((Path(__file__).with_name("models.json")).read_text())


class OpenStudentAidTests(unittest.TestCase):
    def test_model_fixture_and_money_parsing(self):
        loans = _loan_list(MODELS)
        self.assertEqual(len(loans), 2)
        self.assertEqual(_money("$1,234.56"), 1234.56)
        self.assertEqual(_money("(42.10)"), -42.10)
        self.assertEqual(_loan_total(loans[0]), 1015.50)
        self.assertEqual(_loan_total(loans[1]), 2012.50)

    def test_mfa_matching_uses_visible_labels(self):
        self.assertRegex("Text message to ending in 12", _method_pattern("sms"))
        self.assertRegex("Email code to a***@example.com", _method_pattern("email"))
        self.assertRegex("Authenticator app", _method_pattern("authenticator"))

    def test_sensitive_debug_values_are_redacted(self):
        self.assertEqual(
            _redact("user=alice password=secret", ["alice", "secret"]),
            "user=[REDACTED] password=[REDACTED]",
        )

    def test_mfa_code_resolution(self):
        self.assertEqual(
            _resolve_mfa_code(get_code=lambda prompt: "12 34 56", mfa_code=None),
            "123456",
        )
        with patch.dict(os.environ, {"STUDENT_AID_MFA_CODE": "999999"}):
            self.assertEqual(_resolve_mfa_code(get_code=None, mfa_code="123456"), "123456")

    def test_session_state_is_secure_and_public_summary_is_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"OSA_STORAGE_DIR": directory}):
                LAST_SESSION_STATES["nelnet"] = {"cookies": [], "origins": []}
                path = save_core_session("nelnet")
                self.assertEqual(json.loads(Path(path).read_text()), {"cookies": [], "origins": []})
                self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
                LAST_SESSION_STATES.pop("nelnet", None)

        self.assertTrue(callable(open_studentaid.loan_snapshot))
        self.assertTrue(hasattr(open_studentaid.StudentAid(), "save_session"))


if __name__ == "__main__":
    unittest.main()
