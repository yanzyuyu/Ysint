import unittest
from ysint.utils import is_ipv4, is_domain, is_email, is_phone_number
from ysint.modules.ip import scan_ip
from ysint.modules.email import scan_email
from ysint.modules.subdomain import resolve_target
from ysint.modules.username import scan_username
from ysint.modules.phone import scan_phone

class TestYsintModules(unittest.TestCase):

    def test_utils_validators(self):
        self.assertTrue(is_ipv4("1.1.1.1"))
        self.assertTrue(is_ipv4("192.168.1.50"))
        self.assertFalse(is_ipv4("github.com"))
        self.assertFalse(is_ipv4("999.999.999.999"))

        self.assertTrue(is_phone_number("+6281234567890"))
        self.assertTrue(is_phone_number("081234567890"))
        self.assertTrue(is_phone_number("+1-800-555-0199"))
        self.assertFalse(is_phone_number("yanzyuyu"))
        self.assertFalse(is_phone_number("hello@domain.com"))

        self.assertTrue(is_domain("github.com"))
        self.assertTrue(is_domain("sub.domain.co.id"))
        self.assertFalse(is_domain("justastring"))
        self.assertFalse(is_domain("http://github.com"))

        self.assertTrue(is_email("admin@domain.com"))
        self.assertTrue(is_email("first.last+tag@sub.domain.org"))
        self.assertFalse(is_email("notanemail"))
        self.assertFalse(is_email("@missinguser.com"))

    def test_ip_special_scopes(self):
        priv_res = scan_ip("192.168.1.1")
        self.assertTrue(priv_res["is_private"])
        self.assertEqual(priv_res["scope"], "Private")

        loop_res = scan_ip("127.0.0.1")
        self.assertTrue(loop_res["is_private"])
        self.assertEqual(loop_res["scope"], "Loopback")

        invalid_res = scan_ip("not-an-ip")
        self.assertEqual(invalid_res["status"], "error")

    def test_email_intelligence(self):
        invalid = scan_email("not-an-email")
        self.assertFalse(invalid["valid_syntax"])

        disposable = scan_email("anon@mailinator.com", timeout=3.0)
        self.assertTrue(disposable["valid_syntax"])
        self.assertTrue(disposable["is_disposable"])
        self.assertEqual(disposable["domain"], "mailinator.com")

        normal = scan_email("contact@github.com", timeout=3.0)
        self.assertTrue(normal["valid_syntax"])
        self.assertFalse(normal["is_disposable"])
        self.assertIn("pgp_keys", normal)
        self.assertIn("gravatar", normal)
        self.assertIn("osint_pivots", normal)

    def test_subdomain_resolution_schema(self):
        res = resolve_target("www", "google.com")
        self.assertIn("subdomain", res)
        self.assertIn("fqdn", res)
        self.assertIn("ip", res)
        self.assertIn("alive", res)
        self.assertEqual(res["fqdn"], "www.google.com")

    def test_username_scan_structure(self):
        res = scan_username("testuser99881122", timeout=3.0, max_workers=5)
        self.assertEqual(res["target"], "testuser99881122")
        self.assertIn("total_probed", res)
        self.assertIn("total_found", res)
        self.assertIsInstance(res["profiles"], list)
        self.assertIn("osint_pivots", res)

    def test_phone_intelligence(self):
        id_mobile = scan_phone("+6281234567890")
        self.assertTrue(id_mobile["valid"])
        self.assertEqual(id_mobile["country"], "Indonesia")
        self.assertEqual(id_mobile["calling_code"], "+62")
        self.assertEqual(id_mobile["line_type"], "Mobile")
        self.assertIn("Telkomsel", id_mobile["carrier"])
        self.assertIn("whatsapp", id_mobile["osint_pivots"])
        self.assertIn("kredibel", id_mobile["osint_pivots"])
        self.assertIn("tellows", id_mobile["osint_pivots"])

        nat_mobile = scan_phone("085712345678")
        self.assertTrue(nat_mobile["valid"])
        self.assertEqual(nat_mobile["e164"], "+6285712345678")
        self.assertIn("Indosat", nat_mobile["carrier"])

        us_num = scan_phone("+1-415-555-2671")
        self.assertTrue(us_num["valid"])
        self.assertEqual(us_num["calling_code"], "+1")
        self.assertIn("San Francisco", us_num["carrier"])

        invalid = scan_phone("123")
        self.assertFalse(invalid["valid"])

if __name__ == "__main__":
    unittest.main()
