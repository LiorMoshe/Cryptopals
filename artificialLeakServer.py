'''
This is the server that we will use in challenge 31:attacking HMAC-SHA1
using artificial timing leaks.
We will show that implementation of insecure_compare is insecure (by using the
artificial timing leak).
'''
import web
from funcs import hmac
from sha1 import sha1
from os import urandom
from time import sleep

RAND_KEY = urandom(64)

def insecure_compare(first,second):
    '''
    Compares one byte at a time,this is used to implement
    the timing leak attack.
    Exit once we find two different bytes at matching positions.
    :param first: First argument to be compared.
    :param second: Second argument to be compared.
    :return: 500 if the MAC is invalid,200 otherwise(HTTP codes).
    '''
    try:
        for i in range(len(first)):
            #Sleep 50 ms in eacg iteration.
            sleep(0.05)
            if (first[i] != second[i]):
                return 500
    except IndexError:
        return 500
    return 200

urls = (
    '/test', 'index'
)

class index:
    def GET(self):

    	#Extract user input.
    	storage = web.input(file = None,signature = None)
    	file_name = storage.file
    	signature = storage.signature

    	#Open the file and test signature.
        try:
            my_file_info = open(file_name, 'r').read()
        except IOError:
            return "Given file name is not found."
    	print my_file_info
    	res = hmac(sha1,RAND_KEY,my_file_info,64)
        print "Random hmac for this file: " + res
    	return insecure_compare(res,signature)

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()


