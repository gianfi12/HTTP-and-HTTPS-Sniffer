from netfilterqueue import NetfilterQueue
import threading
import psutil
import time

nfqueue=NetfilterQueue()

def PrintException():
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    print 'EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)


def control():
    while True:
        print psutil.cpu_percent(interval=1), psutil.phymem_usage().percent
        print
        time.sleep(10)

def print_and_accept(pkt):
    #print pkt
    pkt.accept()

def queue(coda):
    print coda
    nfqueue.bind(coda,print_and_accept)
    nfqueue.run()


t=threading.Thread(target=control)
p1=threading.Thread(target=queue, args=(128,))
p2=threading.Thread(target=queue, args=(192,))
t.start()
print t.isAlive()
p1.start()
print p1.isAlive()
p2.start()
print p2.isAlive()
p1.join()
p2.join()
t.join()
