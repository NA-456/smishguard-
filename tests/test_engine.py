"""
SmishGuard test suite.
Run with: pytest tests/ -v
"""

import pytest
from app.engine import analyze_message, toggle_rule, set_rule_weight


# ── Engine unit tests ────────────────────────────────────────────────

class TestGlobalRules:
    def test_clean_message_is_safe(self):
        r = analyze_message("Your appointment is confirmed for tomorrow at 9am.")
        assert r["level"] == "safe"

    def test_shortened_url_detected(self):
        r = analyze_message("Click here: http://bit.ly/get-prize")
        assert any(t["id"] == "url_shortener" for t in r["triggered_rules"])

    def test_urgency_language_detected(self):
        r = analyze_message("URGENT: Your account will be suspended. Act now!")
        assert any(t["id"] == "urgency" for t in r["triggered_rules"])

    def test_credential_request_detected(self):
        r = analyze_message("Please verify your account and enter your OTP to continue.")
        assert any(t["id"] == "credential_request" for t in r["triggered_rules"])

    def test_ip_url_detected(self):
        r = analyze_message("Login here: https://192.168.1.1/verify-account")
        assert any(t["id"] == "suspicious_url" for t in r["triggered_rules"])

    def test_score_capped_at_100(self):
        # Trigger many rules at once
        r = analyze_message(
            "URGENT: verify your account now at https://192.168.0.1/secure-login "
            "enter your password and pin before your account expires http://bit.ly/x"
        )
        assert r["score"] <= 100


class TestGhanaRules:
    def test_momo_pin_request_detected(self):
        r = analyze_message("Please send your MoMo PIN to confirm your wallet.")
        assert any(t["id"] == "momo_pin_request" for t in r["triggered_rules"])
        assert r["gh_hits"] >= 1

    def test_accidental_transfer_lure(self):
        r = analyze_message("I mistakenly sent GHS 300 to your number. Please send it back.")
        assert any(t["id"] == "momo_accidental_transfer" for t in r["triggered_rules"])

    def test_fake_momo_credit(self):
        r = analyze_message(
            "You have received GHS 500.00 from KWAME ASANTE. "
            "Transaction ID: TXN9283741. Please call 0271122334 to confirm."
        )
        assert any(t["id"] == "momo_fake_credit" for t in r["triggered_rules"])

    def test_mtn_prize_scam(self):
        r = analyze_message(
            "Congratulations! You've won the MTN Ghana Weekly Draw! "
            "Claim GHS 5,000 at http://bit.ly/mtn-claim"
        )
        assert any(t["id"] in ("mtn_prize_scam", "mtn_impersonation") for t in r["triggered_rules"])
        assert r["level"] == "danger"

    def test_mtn_kyc_scam(self):
        r = analyze_message(
            "Dear valued MTN customer, your SIM will be deactivated. "
            "Complete your KYC update immediately."
        )
        assert any(t["id"] in ("mtn_impersonation", "sim_kyc_fraud") for t in r["triggered_rules"])

    def test_telecel_impersonation(self):
        r = analyze_message(
            "TELECEL GHANA: Your account is suspended. Verify at http://telecel-gh-verify.com"
        )
        assert any(t["id"] == "telecel_impersonation" for t in r["triggered_rules"])

    def test_gra_lure(self):
        r = analyze_message(
            "Ghana Revenue Authority (GRA): You are eligible for a GHS 847 tax refund. "
            "Verify your TIN at http://gra-refund-gh.com"
        )
        assert any(t["id"] == "gra_impersonation" for t in r["triggered_rules"])
        assert r["level"] == "danger"

    def test_ec_voter_scam(self):
        r = analyze_message(
            "Electoral Commission Ghana: Your voter ID card is ready. "
            "Pay GHS 15 processing fee to avoid cancellation."
        )
        assert any(t["id"] == "ec_impersonation" for t in r["triggered_rules"])

    def test_cocobod_job_scam(self):
        r = analyze_message(
            "COCOBOD recruiting 500 field officers. Salary GHS 3,800/month. "
            "Send CV and GHS 50 processing fee via MoMo."
        )
        assert any(t["id"] == "gh_job_scam" for t in r["triggered_rules"])

    def test_gh_bank_impersonation(self):
        r = analyze_message(
            "Dear GCB account holder, your card has been blocked. "
            "Verify your details immediately."
        )
        assert any(t["id"] == "gh_bank_impersonation" for t in r["triggered_rules"])

    def test_slang_phishing(self):
        r = analyze_message("Charle momo me, I mistakenly sent to your number bro.")
        assert any(t["id"] in ("gh_slang_phishing", "momo_accidental_transfer") for t in r["triggered_rules"])

    def test_legitimate_otp_is_safe(self):
        r = analyze_message(
            "Your MTN MoMo verification code is 847291. "
            "Valid for 5 minutes. Do not share."
        )
        # Should not be danger — legitimate OTPs shouldn't trigger high-weight rules
        assert r["level"] in ("safe", "suspicious")

    def test_legitimate_bank_debit_is_safe(self):
        r = analyze_message(
            "GCB Bank: GHS 250.00 debited from *4412 on 15/11/2024. "
            "New balance: GHS 1,842.00. Not you? Call 0302-673-423."
        )
        assert r["level"] in ("safe", "suspicious")


class TestAdminControls:
    def test_toggle_rule_off(self):
        r_before = analyze_message("Click here: http://bit.ly/get-prize")
        assert any(t["id"] == "url_shortener" for t in r_before["triggered_rules"])

        toggle_rule("url_shortener", False)
        r_after = analyze_message("Click here: http://bit.ly/get-prize")
        assert not any(t["id"] == "url_shortener" for t in r_after["triggered_rules"])

        # Re-enable for other tests
        toggle_rule("url_shortener", True)

    def test_weight_override(self):
        set_rule_weight("url_shortener", 1)
        r = analyze_message("Click here: http://bit.ly/get-prize")
        url_trigger = next((t for t in r["triggered_rules"] if t["id"] == "url_shortener"), None)
        assert url_trigger is not None
        assert url_trigger["weight"] == 1

        # Restore
        set_rule_weight("url_shortener", 25)


class TestRecommendations:
    def test_momo_recommendation(self):
        r = analyze_message(
            "Send your MoMo PIN immediately or your account will be suspended. "
            "Call 0244000000 now."
        )
        assert "MoMo PIN" in r["recommendation"] or "momo" in r["recommendation"].lower()

    def test_safe_recommendation(self):
        r = analyze_message("Your prescription is ready for pickup at the pharmacy.")
        assert r["level"] == "safe"
        assert "safe" in r["recommendation"].lower() or "cautious" in r["recommendation"].lower()
