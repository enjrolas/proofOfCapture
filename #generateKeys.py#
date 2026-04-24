from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

outdir = Path("./keys")
outdir.mkdir(parents=True, exist_ok=True)

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Derive public key
public_key = private_key.public_key()

# Save private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),  # use BestAvailableEncryption(...) if you want a passphrase
)

with open(outdir / "private_key.pem", "wb") as f:
    f.write(private_pem)

# Save public key
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(outdir / "public_key.pem", "wb") as f:
    f.write(public_pem)

print("Saved keys to", outdir.resolve())
