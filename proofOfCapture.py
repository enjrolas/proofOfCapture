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
signedPhotoFolder=Path("./signedPhotos")


def calculateChecksum(img):
    # Convert to NumPy array
    arr = np.array(img)
    print("photo dimensions:  %s" % (arr.shape,))
    # red channel (view)
    red = arr[:, :, 0]
    green = arr[:, :, 1]
    blue = arr[:, :, 2]
    
    # sum with a 16-bit accumulator
    redChecksum = red.sum(dtype=np.uint16)
    greenChecksum = green.sum(dtype=np.uint16)
    blueChecksum = blue.sum(dtype=np.uint16)
    totalChecksum = arr.sum(dtype=np.uint16)
    checksumString="totalChecksum:%d,redChecksum:%d,greenChecksum:%d,blueChecksum:%d" % (totalChecksum, redChecksum, greenChecksum, blueChecksum)
    print("total checksum:  %d" % (totalChecksum))
    print("red checksum:  %d" % (redChecksum))
    print("green checksum:  %d" % (greenChecksum))
    print("blue checksum:  %d" % (blueChecksum))
    print(checksumString)
    return totalChecksum, redChecksum, greenChecksum, blueChecksum, checksumString

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
    _, _, _, _, checksum_string = calculateChecksum(img)

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
    _, _, _, _, checksum_string = calculateChecksum(img)

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

    output_path = signedPhotoFolder / "output.png"
    img.save(output_path, exif=exif_data)
    print(f"Signed photo saved to {output_path}")


def main(args):
    if args.publicKey:
        print(load_existing_key("public_key.pem").decode())

    if args.generateKeypair:
        generate_keypair()


    if args.signPhoto:
        sign_photo(args.input)
            

    if args.confirmPhoto:
        verify_photo(args.input)

    if args.showMetadata:
        show_metadata(args.input)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="proof of capture")

    # 2. Add arguments
    parser.add_argument("-i", "--input", help="path to the raw photo to sign")
    parser.add_argument("-o", "--output", help="path to the raw photo to output")
    parser.add_argument("-g", "--generateKeypair", action="store_true", help="generate public/private key pair")
    parser.add_argument("-s", "--signPhoto", action="store_true", help="sign raw photo")
    parser.add_argument("-c", "--confirmPhoto", action="store_true", help="confirm photo's proof of capture")
    parser.add_argument("-p", "--publicKeyFile", help="path to public key file")
    parser.add_argument("-pk", "--publicKey", action="store_true", help="public key as text")
    parser.add_argument("-m", "--showMetadata", action="store_true", help="show all metadata")
    
    args = parser.parse_args()
    main(args)
