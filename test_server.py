import unittest
import requests

class TestJWKS(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def test_jwks_endpoint(self):
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("keys", data)
        for key in data["keys"]:
            self.assertIn("kid", key)
            self.assertIn("alg", key)
            self.assertIn("n", key)

    def test_auth_endpoint(self):
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token.startswith("ey"))

    def test_auth_endpoint_expired(self):
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = response.text
        self.assertTrue(token.startswith("ey"))

if __name__ == "__main__":
    unittest.main()
