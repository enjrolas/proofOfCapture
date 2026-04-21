from PIL import Image
import numpy as np
rawPhoto="rawPhoto.jpg"
print("loading photo %s" % rawPhoto)
img=Image.open(rawPhoto)
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
