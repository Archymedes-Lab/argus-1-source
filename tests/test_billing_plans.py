"""The two licence plans: $15 a month and $79 a year."""
import json
import unittest
from unittest import mock

from jarvis.web import billing


class FakeStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key):
        return self.meta.get(key)

    def set_meta(self, key, value):
        self.meta[key] = value


class PlanTests(unittest.TestCase):
    def test_prices(self):
        self.assertEqual(billing.PLANS, {"month": 15, "year": 79})
        status = billing.status(FakeStore())
        self.assertEqual(status["plans"], {"month": 15, "year": 79})
        self.assertEqual(status["price_usd"], 79)   # older callers keep the yearly price

    def test_unknown_plan_is_the_yearly_plan(self):
        for value in (None, "", "weekly", 5, "YEAR "):
            self.assertEqual(billing.plan_of(value), "year")
        self.assertEqual(billing.plan_of("Month"), "month")

    def _checkout_form(self, plan, env=None):
        seen = {}

        def fake(method, path, form=None, timeout=20):
            seen.update(form or {})
            return {"url": "https://checkout.stripe.com/c/pay/x"}, ""
        with mock.patch.object(billing, "configured", return_value=True), \
             mock.patch.object(billing, "setting", side_effect=lambda n: (env or {}).get(n, "")), \
             mock.patch.object(billing, "_stripe", side_effect=fake):
            result = billing.checkout("http://localhost:8787", plan)
        self.assertIn("url", result)
        return seen

    def test_monthly_checkout_is_fifteen_dollars_a_month(self):
        form = self._checkout_form("month")
        self.assertEqual(form["line_items[0][price_data][unit_amount]"], "1500")
        self.assertEqual(form["line_items[0][price_data][recurring][interval]"], "month")
        self.assertEqual(form["metadata[plan]"], "month")

    def test_yearly_checkout_is_seventy_nine_dollars_a_year(self):
        form = self._checkout_form("year")
        self.assertEqual(form["line_items[0][price_data][unit_amount]"], "7900")
        self.assertEqual(form["line_items[0][price_data][recurring][interval]"], "year")
        self.assertEqual(form["metadata[plan]"], "year")

    def test_each_plan_uses_its_own_stripe_price_id(self):
        env = {"STRIPE_PRICE_ID": "price_year", "STRIPE_PRICE_ID_MONTHLY": "price_month"}
        self.assertEqual(self._checkout_form("month", env)["line_items[0][price]"], "price_month")
        self.assertEqual(self._checkout_form("year", env)["line_items[0][price]"], "price_year")

    def test_licence_length_follows_the_plan(self):
        for plan, term in (("month", 32 * 86400), ("year", 366 * 86400), (None, 366 * 86400)):
            store = FakeStore()
            session = {"id": "cs_test_x", "metadata": {"plan": plan} if plan else {}}
            billing._grant(store, session, 1000)
            record = json.loads(store.meta[billing.META_KEY])
            self.assertEqual(record["expires"], 1000 + term)
            self.assertEqual(billing.status(store, 1001)["plan"], plan or "year")


if __name__ == "__main__":
    unittest.main()
