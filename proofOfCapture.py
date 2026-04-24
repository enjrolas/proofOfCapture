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

keyFolder=Path("./keys")
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



def main(argv=None):
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
    
    args = parser.parse_args(argv)

    if args.publicKey:
        with open(keyFolder / "public_key.pem", "rb") as key_file:
            publicKey=key_file.read()
            print(publicKey)
            
    if args.generateKeypair:
        keyFolder.mkdir(parents=True, exist_ok=True)
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
        
        with open(keyFolder / "private_key.pem", "wb") as f:
            f.write(private_pem)
            
            # Save public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            
        with open(keyFolder / "public_key.pem", "wb") as f:
            f.write(public_pem)
            
        print("Saved keys to", keyFolder.resolve())
        
    

    if args.signPhoto:
        inputPhoto=args.input
        print("loading photo %s" % inputPhoto)
        img=Image.open(inputPhoto)        
        totalChecksum, redChecksum, greenChecksum, blueChecksum, checksumString=calculateChecksum(img)

        # load PEM-encoded private key
        with open(keyFolder /"private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            
            message = checksumString.encode("utf-8")
        
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            #get all the metadata tags and build a tag dictionary
            exif = {
                PIL.ExifTags.TAGS[k]: v
                for k, v in img._getexif().items()
                if k in PIL.ExifTags.TAGS
            }
            
            exif_data = img.getexif()
            # Alternatively, use the Base enum for readability
            decodedSignature=base64.b64encode(signature).decode()
            exif_data[Base.ImageDescription] = decodedSignature

            # 4. Save with the updated EXIF data
            outputFilepath=signedPhotoFolder/"output.png"
            img.save(outputFilepath, exif=exif_data)
            

    if args.confirmPhoto:
        inputPhoto=args.input
        print("loading photo %s" % inputPhoto)
        img=Image.open(inputPhoto)        
        totalChecksum, redChecksum, greenChecksum, blueChecksum, checksumString=calculateChecksum(img)
        
        message = checksumString.encode("utf-8")
        exif_data = img.getexif()    

        decodedSignature=exif_data[Base.ImageDescription]
        encodedSignature=base64.b64decode(decodedSignature)
        

        #def verify_image_signature(public_key_path, image_data_path, signature_path):
        # 1. Load the camera manufacturer's public key
        with open(keyFolder / "public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
            

            print("encoded signature:  %s" % encodedSignature)
            print("decoded signature:  %s" % decodedSignature)
            print("message:  %s" % message)
            # 3. Verify the signature
            try:
                public_key.verify(
                    encodedSignature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Verification successful: The image is authentic and unmodified.")
                return True
            
            except InvalidSignature:
                print("Verification failed: The image has been altered or the signature is invalid.")
                return False
                    

        print("checksum string:  %s" % checksumString)
        print("image description from the image:  %s" % exif_data[Base.ImageDescription])
        print("base-64 decoded signature that we just calculated: %s" % decodedSignature)
        

        
        
    if args.showMetadata:
        inputPhoto=args.input
        print("loading photo %s" % inputPhoto)
        img=Image.open(inputPhoto)        

        
        #get all the metadata tags and build a tag dictionary
        exif = {
            PIL.ExifTags.TAGS[k]: v
            for k, v in img._getexif().items()
            if k in PIL.ExifTags.TAGS
        }
        pprint(exif)
        pprint(img._getexif().items())
        
            

            
        

if __name__ == "__main__":
    # Passing sys.argv[1:] allows for easier testing/calling from other modules
    main()
