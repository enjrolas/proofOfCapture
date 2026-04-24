import c2pa
from c2pa import Reader

with open("rawPhoto.jpg", "rb") as f:
    with Reader("image/jpeg", f) as reader:
        print(reader.json())



