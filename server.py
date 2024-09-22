#Name: Harshil Vanparia
#COURSE: CSCE 3550
#Project 1

from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  # Import the default_backend function
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
from calendar import timegm
import json
import jwt

# In-memory storage for key pairs with key ID (kid), private key, and expiry
keys_store = []

# Function to generate and store RSA keys with a kid and expiry
def generate_keys():
    for i in range(5):
        # Add the backend argument to the generate_private_key function
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        priv_key_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kid = f"key-{i}"
        expiry = datetime.now(tz=timezone.utc) + (timedelta(hours=1) if i % 2 else timedelta(hours=-1))
        keys_store.append({"kid": kid, "key": priv_key_bytes, "exp": timegm(expiry.timetuple())})

# Generate initial set of keys
generate_keys()

# Custom request handler class
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # JWKS Endpoint to serve active keys
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.end_headers()
            jwks = {"keys": []}
            for key_info in keys_store:
                print(f"Checking Key: {key_info['kid']} with Expiry: {key_info['exp']}")
                if key_info["exp"] > timegm(datetime.now(tz=timezone.utc).timetuple()):
                    priv_key = serialization.load_pem_private_key(key_info["key"], None, backend=default_backend())
                    pub_key = priv_key.public_key()
                    jwk = {
                        "kid": key_info["kid"],
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "n": base64url_encode(bytes_from_int(pub_key.public_numbers().n)).decode("UTF-8"),
                        "e": base64url_encode(bytes_from_int(pub_key.public_numbers().e)).decode("UTF-8"),
                    }
                    jwks["keys"].append(jwk)
                    print(f"Adding Key: {key_info['kid']} to JWKS Response")
            print(f"JWKS Response: {json.dumps(jwks, indent=1)}")
            self.wfile.write(json.dumps(jwks, indent=1).encode("UTF-8"))
            return
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # Authentication Endpoint to issue JWTs
        if self.path.startswith("/auth"):
            expired = "expired=true" in self.path
            self.send_response(200)
            self.end_headers()
            for key_info in keys_store:
                if (expired and key_info["exp"] <= timegm(datetime.now(tz=timezone.utc).timetuple())) or (
                    not expired and key_info["exp"] > timegm(datetime.now(tz=timezone.utc).timetuple())
                ):
                    jwt_token = jwt.encode(
                        {"exp": key_info["exp"]},
                        key_info["key"],
                        algorithm="RS256",
                        headers={"kid": key_info["kid"]},
                    )
                    self.wfile.write(jwt_token.encode("UTF-8"))
                    return
            self.wfile.write(b'{"error": "No valid key found"}')
            return
        else:
            self.send_response(404)
            self.end_headers()

# Create HTTP server on localhost:8080
http_server = HTTPServer(("", 8080), RequestHandler)
print("HTTP Server running on Localhost port 8080...")

try:
    http_server.serve_forever()  # Run the server forever
except KeyboardInterrupt:
    pass
http_server.server_close()  # Close the server
