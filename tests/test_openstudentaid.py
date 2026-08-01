from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import open_studentaid
from open_studentaid.api import (
    _loan_list,
    _loan_total,
    _money,
    loan_details,
    loan_snapshot,
    loan_summary,
)
from open_studentaid.edfinancial.api import (
    _persist_browser_session,
    parse_account_summary,
)
from open_studentaid.edfinancial.auth import clear_stale_session_cookies
from open_studentaid.exceptions import LoginFlowError
from open_studentaid.openstudentaid import (
    _method_pattern,
    _normalize_date_of_birth,
    _normalize_social_security_number,
    _redact,
    _resolve_mfa_code,
    _select_mfa_method,
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

    def test_mfa_error_names_selected_provider(self):
        class EmptyPage:
            def locator(self, selector):
                raise RuntimeError(selector)

        with self.assertRaisesRegex(
            LoginFlowError,
            "Edfinancial did not show an MFA option",
        ):
            _select_mfa_method(
                EmptyPage(), "sms", provider="edfinancial"
            )

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

    def test_identity_value_normalization(self):
        self.assertEqual(_normalize_date_of_birth("12/18/2003"), ("12", "18", "2003"))
        self.assertEqual(
            _normalize_social_security_number("123-45-6789"),
            ("123", "45", "6789"),
        )

    def test_edfinancial_account_summary_parser(self):
        html = Path(__file__).with_name("edfinancial_summary.html").read_text()
        data = parse_account_summary(
            html,
            "Total Current Balance: $5,500.25\nTotal Number of Loans: 2",
        )

        self.assertEqual(data["totalCurrentBalance"], 5500.25)
        self.assertEqual(data["totalNumberOfLoans"], 2)
        self.assertEqual(data["loans"][0]["loanId"], "101")
        self.assertEqual(data["loans"][0]["currentBalance"], 1000.25)
        self.assertEqual(data["loans"][1]["interestRate"], 5.5)

    def test_edfinancial_rotated_session_is_persisted(self):
        refreshed_state = {
            "cookies": [{"name": "rotated", "value": "new"}],
            "origins": [],
        }

        class Context:
            def storage_state(self):
                return refreshed_state

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "edfinancial" / "storage_state.json"
            _persist_browser_session(Context(), path)

            self.assertEqual(json.loads(path.read_text()), refreshed_state)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_edfinancial_login_clears_only_transient_servicer_cookies(self):
        class Context:
            def __init__(self):
                self.cleared = []

            def cookies(self):
                return [
                    {
                        "name": "JSESSIONID",
                        "domain": "authenticate2.edfinancial.studentaid.gov",
                        "path": "/CALM2EDF",
                        "expires": -1,
                    },
                    {
                        "name": "remembered-device",
                        "domain": "authenticate2.edfinancial.studentaid.gov",
                        "path": "/",
                        "expires": 2_000_000_000,
                    },
                    {
                        "name": "unrelated-session",
                        "domain": "example.com",
                        "path": "/",
                        "expires": -1,
                    },
                ]

            def clear_cookies(self, **kwargs):
                self.cleared.append(kwargs)

        context = Context()
        clear_stale_session_cookies(context)

        self.assertEqual(
            context.cleared,
            [
                {
                    "name": "JSESSIONID",
                    "domain": "authenticate2.edfinancial.studentaid.gov",
                    "path": "/CALM2EDF",
                }
            ],
        )

    def test_public_calls_dispatch_to_edfinancial(self):
        raw = {
            "provider": "edfinancial",
            "totalCurrentBalance": 5500.25,
            "totalNumberOfLoans": 2,
            "loans": [
                {
                    "loanId": "101",
                    "loanTypeDescription": "Direct Loan - Unsubsidized",
                    "servicerName": "Edfinancial",
                    "status": "In Grace",
                    "interestRate": 4.99,
                    "currentBalance": 5500.25,
                }
            ],
        }
        with patch(
            "open_studentaid.api._edfinancial_borrower_details", return_value=raw
        ):
            total, count, returned = loan_summary(provider="edfinancial")
            details = loan_details(provider="edfinancial")
            snapshot = loan_snapshot(provider="edfinancial")

        self.assertEqual((total, count), (5500.25, 2))
        self.assertIs(returned, raw)
        self.assertEqual(details[0]["servicer"], "Edfinancial")
        self.assertEqual(details[0]["totalBalance"], 5500.25)
        self.assertEqual(snapshot["loanCount"], 2)

    def test_public_calls_dispatch_to_nelnet(self):
        with patch("open_studentaid.api._nelnet_borrower_details", return_value=MODELS):
            total, count, returned = loan_summary(provider="nelnet")

        self.assertEqual(total, 3028.0)
        self.assertEqual(count, 2)
        self.assertIs(returned, MODELS)

    def test_unknown_provider_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported provider"):
            loan_summary(provider="unknown")

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
