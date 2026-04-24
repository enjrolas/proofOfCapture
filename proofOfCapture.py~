from PIL import Image
import argparse
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import numpy as np
from pprint import pprint

keyFolder=Path("./keys")
outdir.mkdir(parents=True, exist_ok=True)

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
    return totalChecksum, redChecksum, greenChecksum, blueChecksum



def main(argv=None):
    parser = argparse.ArgumentParser(description="proof of capture")

    # 2. Add arguments
    parser.add_argument("-r", "--rawPhoto", help="path to the raw photo to sign")
    parser.add_argument("-g", "--generateKeypair", action="store_true", help="generate public/private key pair")
    parser.add_argument("-s", "--signPhoto", action="store_true", help="sign raw photo")
    parser.add_argument("-s", "--confirmPhoto", help="sign raw photo")
    parser.add_argument("-o", "--outputFile", help="output file")
    parser.add_argument("-p", "--publicKeyFile", help="path to public key file")
    parser.add_argument("-pk", "--publicKey", help="public key as text")
    parser.add_argument("-k", "--printPublicKey", action="store_true", help="print public key")

    args = parser.parse_args(argv)

    if args.signPhoto:
        rawPhoto=args.rawPhoto
        print("loading photo %s" % rawPhoto)
        img=Image.open(rawPhoto)        
        totalChecksum, redChecksum, greenChecksum, blueChecksum=calculateChecksum(img)

        # load PEM-encoded private key
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            
            message = "hello world".encode("utf-8")
        
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )


            #now write the signed checksum to exif data
            exif = img.getexif()
            print("image metadata")
            pprint(exif)
        
            # Build reverse lookup (name → id)
            tag_map = {v: k for k, v in ExifTags.TAGS.items()}
            pprint(tag_map)        




if __name__ == "__main__":
    # Passing sys.argv[1:] allows for easier testing/calling from other modules
    main()
