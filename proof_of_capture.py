#!/usr/bin/env python3
from PIL import Image
import argparse
import PIL.ExifTags
from PIL.ExifTags import Base
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
import numpy as np
from pprint import pprint
import base64

key_folder=Path("./keys")
signed_photo_folder=Path("./signedPhotos")


def calculate_checksum(img):
    # Convert to NumPy array
    arr = np.array(img)
    print("photo dimensions:  %s" % (arr.shape,))
    # red channel (view)
    red = arr[:, :, 0]
    green = arr[:, :, 1]
    blue = arr[:, :, 2]
    
    # sum with a 16-bit accumulator
    red_checksum = red.sum(dtype=np.uint16)
    green_checksum = green.sum(dtype=np.uint16)
    blue_checksum = blue.sum(dtype=np.uint16)
    total_checksum = arr.sum(dtype=np.uint16)
    checksum_string="total_checksum:%d,red_checksum:%d,green_checksum:%d,blue_checksum:%d" % (total_checksum, red_checksum, green_checksum, blue_checksum)
    print("total checksum:  %d" % (total_checksum))
    print("red checksum:  %d" % (red_checksum))
    print("green checksum:  %d" % (green_checksum))
    print("blue checksum:  %d" % (blue_checksum))
    print(checksum_string)
    return total_checksum, red_checksum, green_checksum, blue_checksum, checksum_string

def load_existing_key(path: str) -> str:
    with open(key_folder / path, "rb") as key_file:
        return key_file.read()


def generate_keypair():
    key_folder.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_folder / "private_key.pem", "wb") as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(key_folder / "public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Saved keys to", key_folder.resolve())


def show_metadata(input_path):
    print(f"loading photo {input_path}")
    img = Image.open(input_path)
    exif = {
        PIL.ExifTags.TAGS[k]: v
        for k, v in img._getexif().items()
        if k in PIL.ExifTags.TAGS
    }
    pprint(exif)


def verify_photo(input_path):
    print(f"loading photo {input_path}")
    img = Image.open(input_path)
    _, _, _, _, checksum_string = calculate_checksum(img)

    exif_data = img.getexif()
    signature = base64.b64decode(exif_data[Base.ImageDescription])

    with open(key_folder / "public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            checksum_string.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Verification successful: The image is authentic and unmodified.")
        return True
    except InvalidSignature:
        print("Verification failed: The image has been altered or the signature is invalid.")
        return False


def sign_photo(input_path):
    print(f"loading photo {input_path}")
    img = Image.open(input_path)
    _, _, _, _, checksum_string = calculate_checksum(img)

    with open(key_folder / "private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        checksum_string.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    exif_data = img.getexif()
    exif_data[Base.ImageDescription] = base64.b64encode(signature).decode()

    output_path = signed_photo_folder / "output.png"
    img.save(output_path, exif=exif_data)
    print(f"Signed photo saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="proof of capture")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("generate", help="generate public/private key pair")
    subparsers.add_parser("public-key", help="print public key")

    sign_parser = subparsers.add_parser("sign", help="sign a photo")
    sign_parser.add_argument("photo", help="path to the photo to sign")

    verify_parser = subparsers.add_parser("verify", help="verify a signed photo")
    verify_parser.add_argument("photo", help="path to the signed photo")

    metadata_parser = subparsers.add_parser("metadata", help="show EXIF metadata")
    metadata_parser.add_argument("photo", help="path to the photo")

    args = parser.parse_args()

    if args.command == "generate":
        generate_keypair()
    elif args.command == "public-key":
        print(load_existing_key("public_key.pem").decode())
    elif args.command == "sign":
        sign_photo(args.photo)
    elif args.command == "verify":
        verify_photo(args.photo)
    elif args.command == "metadata":
        show_metadata(args.photo)


if __name__ == "__main__":
    main()
