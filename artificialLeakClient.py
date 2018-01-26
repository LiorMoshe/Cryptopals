'''
This is the client that uses the artificial timing leak
to discover the hmac of any file under some random key.
In this example we hard-coded the name of the file that we look
for it's signature(foo) for simplicity,we could use it for any other file
by setting the variable FILE_NAME via some user input.
'''
from urllib import urlopen
import time


#The name of the file that we look for it's signature.
FILE_NAME = "foo"

#The url we will turn to.
URL = "http://localhost:8080/test?file=" + FILE_NAME + "&signature="

def num_to_hex(num):
    return hex(num).split('x')[1]

def discover_char(found_sig):
    '''
    This function will use the artificial timing leak that is implemented
    in the server to discover one character of the signature of this file.
    We will pass over all the 16 available hex characters and check which character
    made the server work for the longest time,this character is the next character
    in the secret signature of the file.
    :param found_sig: The characters of the signature that were found so far.
    :return: The next character in the signature.
    '''
    max_time = 0
    curr_url = URL + found_sig
    for i in range(16):
        curr_char = num_to_hex(i)
        start_time = time.time()
        response = urlopen(curr_url + curr_char)
        total_time = time.time() - start_time

        #Test if the time taken is longer.
        if total_time > max_time:
            best_char = curr_char
            max_time = total_time

    #Return the char which led to max_time.
    return best_char
