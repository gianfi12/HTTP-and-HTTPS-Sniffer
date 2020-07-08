import random

x="52:54:00:%02x:%02x:%02x" % (
     random.randint(0, 255),
     random.randint(0, 255),
     random.randint(0, 255),
     )
print x
