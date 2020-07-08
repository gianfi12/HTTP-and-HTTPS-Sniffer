import subprocess

p=subprocess.Popen(['./a.out','br0'], bufsize=-1, stdout=subprocess.PIPE)
k=0
try:
    for row in p.stdout:
        x=row
except KeyboardInterrupt:
    print k

# './a.out','br0'
# 'tcpdump','-l','-i','br0','-B','65536','-w','-'
