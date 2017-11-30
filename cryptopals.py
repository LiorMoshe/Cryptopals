'''Implementation of the cryptopals crypto challenges.
The program will get TWO command line arguments.
The first argument will represent the number of set of the crypto challenges
we will run and the second number will represent the number of challenge in this set
that will be run.
In this program I assume both cmd arguments are strings of integers.
Lior Moshe 2017'''
import base64
from Crypto.Cipher import AES
import math
import os
import json
import sys
import random
import struct
import time
from collections import OrderedDict

'''This dictionary will hold all statistical information about frequency of letters and their combinations
in english in order to help us rate given texts written in english letters.
All statistics are taken from: http://scottbryce.com/cryptograms/stats.htm'''
letters_frequency = {
	'E': 12.51,
	'T': 9.25,
	'A': 8.04,
	'O': 7.60,
	'I': 7.26,
	'N': 7.09,
	'S': 6.54,
	'R': 6.12,
	'H': 5.49,
	'L': 4.14,
	'D': 3.99,
	'C': 3.06,
	'U': 2.71,
	'M': 2.53,
	'F': 2.30,
	'P': 2.00,
	'G': 1.96,
	'W': 1.92,
	'Y': 1.73,
	'B': 1.54,
	'V': 0.99,
	'K': 0.67,
	'X': 0.19,
	'J': 0.16,
	'Q': 0.11,
	'Z': 0.09
}

common_digraphs = {
	'TH':1,
	'HE':26/27,
	'AN':25/27,
	'IN':24/27,
	'ER':23/27,
	'ON':22/27,
	'RE':21/27,
	'ED':20/27,
	'ND':19/27,
	'HA':18/27,
	'AT':17/27,
	'EN':16/27,
	'ES':15/27,
	'OF':14/27,
	'NT':13/27,
	'EA':12/17,
	'TI':11/27,
	'TO':10/27,
	'IO':9/27,
	'LE':8/27,
	'IS':7/27,
	'OU':6/27,
	'AR':5/27,
	'AS':4/27,
	'DE':3/27,
	'RT':2/27,
	'VE':1/27,
	'QU':1/54
}

common_trigraphs = {
	'THE':1,
	'AND':12 / 13,
	'THA':11 / 13,
	'ENT':10 / 13,
	'ION':9 / 13,
	'TIO':8 / 13,
	'FOR':7 / 13,
	'NDE':6 / 13,
	'HAS':5 / 13,
	'NCE':4 / 13,
	'TIS':3 / 13,
	'OFT':2 / 13,
	'MEN':1 / 13
}

#Just because I dont like magic numbers
BYTESIZE = 8

#Overall dictionary for english statistics.
english_stats = {
	'letter_freq': letters_frequency,
	'digraphs': common_digraphs,
	'trigraphs': common_trigraphs
}

#Extract command line argument to know which challenge code to test.
if (len(sys.argv) != 3):
	print("The program receives exactly 2 command line arguments:number of set and number of challenge.")
	exit()
num_set = int(sys.argv[1])
num_challenge = int(sys.argv[2])
'''Set1'''
def hex_to_base64(inp_txt):
	'''
	Challenge1
	Function that converts a hex encoded string and converts it 
	to a bas64 encoded string.We will just use the already implemented python
	functions encode() and decode for python strings.
	Input:Hex encoded string.
	Output:Same string encoded in base64.
	'''
	return inp_txt.decode("hex").encode("base64")

#Test challenge1.
if (num_set == 1 and num_challenge == 1):
	if (hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		== "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n"):
		print("SUCCESS")
	else:
		print("FAILURE:")

def xor_strings(first_str,second_str):
	'''
	Challenge2(a simple xor)
	This function takes two equal length buffers and produces their XOR combination.
	Input:Two strings, if they are not of equal length we will xor based on the length of the
	shorter string.
	Output:XOR result.
	'''
	#Make strings of equal length if they are not already there.
	if (len(first_str) < len(second_str)):
		second_str = second_str[:len(first_str)]
	elif(len(second_str) < len(first_str)):
		first_str = first_str[:len(second_str)]
	return (''.join(chr(ord(a) ^ ord(b)) for a,b in zip(first_str,second_str)))

#Test challenge2.
if (num_set == 1 and num_challenge == 2):
	if (xor_strings("1c0111001f010100061a024b53535009181c".decode("hex"),
				"686974207468652062756c6c277320657965".decode("hex"))
				 == "746865206b696420646f6e277420706c6179".decode("hex")):
				print("SUCCESS")
	else:
		print("FAILURE:")

def count_english_letters(inp_str):
	score = 0.0
	for i in range(len(inp_str)):
		#Small english letters.
		if (ord(inp_str[i]) >= 65 and ord(inp_str[i]) <= 90):
			score += 2
		#Capital english letters.
		elif (ord(inp_str[i]) <= 122 and ord(inp_str[i]) >= 97):
			score += 2
		#Spaces and commas.
		elif (ord(inp_str[i]) == 32 or ord(inp_str[i]) == 44 or ord(inp_str[i]) == 39):
			score += 1
		else:
			score -= 1
	return score

def get_english_score(inp_str):
	'''
	This function will receive a string and give it a definitive score 
	based on the english statistics(such as letter,digraph and trigraph frequencies).
	Input:Some string of english letters.
	Output: Score that represents how likely that this string is a valid english sentene(or some 
		incomplete english sentence).We will normalize the score so that longer string don't get some advantage.
	over shorter strings.
	'''
	score = count_english_letters(inp_str)
	#We will count NONOVERLAPPING occurences of letters,digraph,trigraphs in the string.
	'''for letter,freq in english_stats['letter_freq'].iteritems():
		score += inp_str.count(letter) * freq / 100
	#Digraphs are more important that single letters
	for curr_digraph,freq in english_stats['digraphs'].iteritems():
		score += inp_str.count(curr_digraph) * freq * 5
	for curr_trigraph,freq in english_stats['trigraphs'].iteritems():
		score += inp_str.count(curr_trigraph) * freq * 2'''
	#Return normalized score.
	return score / len(inp_str)

def decrypt_single_byte_xor(ciphertext):
	'''
	Challenge3
	This function will use the get_english_score function that we defined above to find
	the key that was used to create this ciphertext using a single byte xor.We will just
	have to brute-force over all the 256 possibilities and compute all the scores.
	This is obviously easy because xor is symmetric.
	Input:The ciphertext.
	Output: The plaintext and the key that was used to decrypt the ciphertext and the score.
	'''
	best_score = 0.0
	plaintext = None
	key = None
	for i in range(256):
		curr_str = chr(i) * len(ciphertext)
		potential_plaintext = xor_strings(ciphertext,curr_str)
		#Compute score of potential plaintext.
		curr_score = get_english_score(potential_plaintext)
		if (curr_score > best_score):
			key = i
			best_score = curr_score
			plaintext = potential_plaintext
	return plaintext,key,best_score

#Test Challenge3.
if (num_set == 1 and num_challenge == 3):
	plaintext,key,score = decrypt_single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode("hex"))
	print("Decryption result:",plaintext)

#Test challenge4.
if (num_set == 1 and num_challenge == 4):
	'''
	In challenge 4 we got a file full of strings of the same length that ONLY ONE 
	of them was encrypted by a single character using the XOR operation. We will use 
	the code written for challenge3 in order to find this character.
	Note:All the strings in the file are encoded in hex.
	'''
	#Read all lines from the file.Use read mode.
	my_file = open("set1challenge4.txt","r")
	my_strings = my_file.readlines()
	#Remove all \n from strings.
	my_strings = [curr_str.replace("\n","") for curr_str in my_strings]
	#Iterate until we find the max score,the cipher text and the index of the string that was encrypted.
	key = None
	best_score = 0.0
	plaintext = None
	encrypted_str = None
	#Go over all strings until we get to the one with the max score.
	for curr_str in my_strings:
		curr_plaintext,curr_key,curr_score = decrypt_single_byte_xor(curr_str.decode("hex"))
		if (curr_score > best_score):
			key = curr_key
			best_score = curr_score
			plaintext = curr_plaintext
			encrypted_str = curr_str
	print("The final key:",key)
	print("Encrypted string:",encrypted_str)
	print("The plaintext:",plaintext)

def repeating_xor_key(plaintext,key):
	'''
	This function will encrypt the given plaintext using the given key by the
	repeating xor scheme,i.e. xor blocks of the plaintext with the key to result
	in blocks of the ciphertext.
	Notice that because XOR is symmetric encryption and decryption in repeating xor
	scheme is the same.
	Input:The plaintext and the given key.
	Output:The produced ciphertext.
	'''
	ciphertext = ""
	for i in range(0,len(plaintext),len(key)):
		ciphertext += xor_strings(plaintext[i:(i + len(key))],key)
	return ciphertext

#Test challenge5.
if (num_set == 1 and num_challenge == 5):
	'''
	In challenge5 all we have to do is implement the repeating xor key scheme and play
	with it a little bit.
	'''
	encrypted = repeating_xor_key("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal","ICE")
	print(encrypted.encode("hex"))
	decrypted = repeating_xor_key(encrypted,"ICE")
	print(decrypted)

def count_bits(inp_byte):
	'''
	This simple function counts the number of turned on bits in a byte.
	Input:An input byte.
	Output:The number of turned on bits.
	'''
	cnt = 0
	for i in range(BYTESIZE):
		cnt += 1 & inp_byte
		inp_byte >>= 1
	return cnt

def hamming_distance(first_str,second_str):
	'''
	This function computes the edit distance/ hamming distance between two
	given strings, which is simply the number of different bits between
	the strings(in matching indexes). We wil note that the strings have to be of
	the same length,otherwise the hamming distance isn't defined.
	All we have to do is count the number of 1's bits in the xor of those two strings.
	Input:Two strings of the same length.
	Output:The hamming distance.
	'''
	if (len(first_str) != len(second_str)):
		raise ValueError("Strings must be of same length in order to compute hamming distance.")
	xored_res = xor_strings(first_str,second_str)
	dist = 0
	for i in range(len(xored_res)):
		dist += count_bits(ord(xored_res[i]))
	return dist

def extract_keysize_block(text,num_block,keysize):
	'''
	Simple function, just makes the code more readable.
	'''
	return text[(num_block - 1) * keysize: min(num_block * keysize,len(text))]



def find_keysize(ciphertext,smallest_keysize,largest_keysize):
	'''
	This function will check the normalized hamming distance between the first two blocks
	of size KEYSIZE in the ciphertext and return the key sizes with the top3 results.
	Input:The ciphertext and the range of key sizes to check.
	Output:Top 3 key sizes.
	'''
	#Kind of ugly with 3 variables but not that bad.
	best_dist = second_best_dist = third_best_dist = sys.maxint
	best_keysize = second_keysize = third_keysize = None
	for key_size in range(smallest_keysize,largest_keysize + 1):
		#Get average of hamming distance of 4 blocks.
		#IMPORTANT make sure the distance is a float
		curr_dist = float(hamming_distance(extract_keysize_block(ciphertext,1,key_size),
			extract_keysize_block(ciphertext,2,key_size)) / key_size)
		curr_dist += hamming_distance(extract_keysize_block(ciphertext,1,key_size),
			extract_keysize_block(ciphertext,3,key_size)) / key_size
		curr_dist +=  hamming_distance(extract_keysize_block(ciphertext,1,key_size),
			extract_keysize_block(ciphertext,4,key_size)) / key_size
		curr_dist +=  hamming_distance(extract_keysize_block(ciphertext,2,key_size),
			extract_keysize_block(ciphertext,3,key_size)) / key_size
		curr_dist +=  hamming_distance(extract_keysize_block(ciphertext,2,key_size),
			extract_keysize_block(ciphertext,4,key_size)) / key_size
		curr_dist +=  hamming_distance(extract_keysize_block(ciphertext,3,key_size),
			extract_keysize_block(ciphertext,4,key_size)) / key_size
		curr_dist /= 6

		print("For keysize: %d got score %f" % (key_size,curr_dist))
		#Evaluate calculated normalized hamming distance.
		if curr_dist < best_dist:
			best_dist = curr_dist
			best_keysize = key_size
		elif curr_dist < second_best_dist:
			second_best_dist = curr_dist
			second_keysize = key_size
		elif curr_dist < third_best_dist:
			third_best_dist = curr_dist
			third_keysize = key_size
	#Return the top3 respectively.
	return best_keysize,second_keysize,third_keysize

def break_repeating_xor(ciphertext,keysize):
	'''
	In this function we will break the repeating xor encryption by transposing the blocks
	of the ciphertext and break each one independently as if it is a single byte xor encryption.
	Input:The ciphertext and the keysize.
	Output:The key that was used to encrypt the ciphertext.
	'''
	#Create the transposed blocks.There are keysize such blocks.
	transposed_blocks = [''] * keysize
	for i in range(0,len(ciphertext),keysize):
		for j in range(min(keysize,len(ciphertext) - i)):
			transposed_blocks[j] += ciphertext[i + j]
	key = ""
	for block in transposed_blocks:
		plaintext,curr_char,score = decrypt_single_byte_xor(block)
		key += chr(curr_char)
	return key


#Test challenge6.
if (num_set == 1 and num_challenge == 6):
	'''
	Things are getting heated in challenge6.
	We got a file that was base64'd after being encrypted with repeating xor key and our goal
	is to decrypt it.
	The method for breaking this encryption is not super complicated.
	At first we will have to try different values for KEYSIZE for some range that we decide earlier on,
	for each KEYSIZE value we will check the hamming distance(normalized) between blocks of size KEYSIZE 
	in the ciphertext,the KEYSIZE with minimal normalized hamming distance is probably the correct KEYSIZE
	because the minimal distance implies that these blocks were created by XOR operation with the same EXACT
	key.
	After finding the key size we will find the key character by character by using the function that we wrote
	in previous challenges that breaks single byte xor key.Concatenating all the bytes gives us the wanted key.
	'''
	#Read the file contents.
	my_file = open("set1challenge6.txt","r")
	ciphertext = my_file.read()
	#Base64 decode.
	ciphertext = base64.b64decode(ciphertext)
	#Test hamming distance function.
	if (hamming_distance("this is a test","wokka wokka!!!") == 37):
		print("SUCCESS hamming distance")
	#Get top3 key sizes.
	f_keysize,s_keysize,t_keysize = find_keysize(ciphertext,2,40)
	print("Top 3:%d %d %d" % (f_keysize,s_keysize,t_keysize))
	#Get key for each keysize.
	f_key = break_repeating_xor(ciphertext,f_keysize)
	s_key = break_repeating_xor(ciphertext,s_keysize)
	t_key = break_repeating_xor(ciphertext,t_keysize)
	print("Key for best key size results:",f_key)
	print("Produced plaintext:",repeating_xor_key(ciphertext,f_key))
	print("Key for second best key size results:",s_key)
	print("Produced plaintext:",repeating_xor_key(ciphertext,s_key))
	print("Key for third best key size results:",t_key)
	print("Produced plaintext:",repeating_xor_key(ciphertext,t_key))

def AES_ECB_decrypt(ciphertext,key):
	'''
	Decrypt a given ciphertext with a given key using AES-128 encryption in the given mode.
	We will use the pycrypto library that already implement the algorithm itself.
	Input:The ciphertext,key.
	Output:The plaintext.
	'''
	obj = AES.new(key,AES.MODE_ECB)
	return obj.decrypt(ciphertext)

def AES_ECB_encrypt(plaintext,key):
	'''
	Encrypt the given plaintext with the given key in AES encryption in ECB mode.
	'''
	obj = AES.new(key,AES.MODE_ECB)
	return obj.encrypt(plaintext)

def detect_AES(ciphertext):
	'''
	In this function we will try to detect if a given ciphertext was encrypted in AES-128 in ECB mode.
	we will use the fact that this encryption is stateless so there could be matching blocks of the size
	of the key(which is 16 bytes here),if there are matching blocks it's a clear symbol that this ciphertext was
	encrypted in AES-128 in ECB mode.
	Input:Ciphertext.
	Output:True if we found use of AES-128-ECB,false otherwise.
	'''
	num_blocks = int(len(ciphertext) / 16)
	for i in range(num_blocks):
		for j in range(i + 1,num_blocks):
			if (extract_keysize_block(ciphertext,i + 1,16) == extract_keysize_block(ciphertext,j + 1,16)):
				return True
	return False

#Test challenge7.
if (num_set == 1 and num_challenge == 7):
	'''
	Read from a file a base64'd content that was encrypted in AES-128 in ECB mode
	we will use the pycrypto library to decrypt it.(Writing AES by ourselves can be rough).
	The given key is YELLOW SUBMARINE
	'''
	my_file = open("set1challenge7.txt","r")
	content = base64.b64decode(my_file.read())
	print("Decrypted:",AES_ECB_decrypt(content,"YELLOW SUBMARINE"))

#Test challenge8.
if (num_set == 1 and num_challenge == 8):
	'''
	In this challenge we will detect the use AES in ECB mode.
	We will do this by using the fact the ECB is STATELESS.
	'''
	my_file = open("set1challenge8.txt","r")
	#Read from the file.
	my_strings = my_file.readlines()
	my_strings = [curr_str.replace("\n","") for curr_str in my_strings]
	for curr_str in my_strings:
		if (detect_AES(curr_str.decode("hex"))):
			print("Detected AES for ciphertext:",curr_str)


def PKCS7(plaintext,blocksize):
	'''
	In this function we will apply PCKS#7 padding for the given plaintext
	with the given blocksize.
	Input:The plaintext and the blocksize that the encryption will work with.
	Output:The padded plaintext with PKCS#7 scheme,i.e. plaintext with x added bytes that
	the value of each one of them is x.
	'''
	num_blocks = math.ceil(float(len(plaintext)) / blocksize)
	remaining = int(num_blocks * blocksize - len(plaintext))
	if (remaining != 0):
		plaintext += chr(remaining) * remaining
	else:
		#Add full block of value blocksize.
		plaintext += chr(blocksize) * blocksize
	return plaintext



#Test challenge9
if (num_set == 2 and num_challenge == 1):
	if (PKCS7("YELLOW SUBMARINE",20) == "YELLOW SUBMARINE\x04\x04\x04\x04"):
		print("SUCCESS")


def AES_CBC_dec(ciphertext,key,iv):
	'''
	In this function we will implement the decryption process of AES in CBC mode
	by using the function that we wrote for AES encryption in ECB mode.
	Input: The ciphertext,the key and the iv that was used to encrypt the plaintext.
	Output:The plaintext,result of the decryption.
	'''
	plaintext = ""
	num_blocks = int(math.ceil(float(len(ciphertext)) / len(key)))
	#print "In decryption got ciphertext:%s number of blocks%d" % (ciphertext,num_blocks)
	#Only do this if there is more than one block.
	if num_blocks > 1:
		for i in range(num_blocks,0,-1):
			current_ciphertext_block = extract_keysize_block(ciphertext,i,len(key))
			curr_block = xor_strings(AES_ECB_decrypt(current_ciphertext_block,key),
								extract_keysize_block(ciphertext,i - 1,len(key)))
			plaintext = curr_block + plaintext
	#For the last block we will use the IV.
	curr_block = xor_strings(AES_ECB_decrypt(extract_keysize_block(ciphertext,0,len(key)),key),iv)
	return (curr_block + plaintext)

def AES_CBC_enc(plaintext,key,iv):
	'''
	Implementation of encryption process of AES in CBC mode.
	We will use the function that we wrote for AES encryption in AES mode.
	Input:plaintext,the key and the iv that we will use.
	Output:The ciphertext.
	'''
	ciphertext = ""
	#Append with PKCS#7 if needed.
	plaintext = PKCS7(plaintext,len(key))
	num_blocks = int(len(plaintext) / len(key))
	#First block uses iv.
	curr_block = AES_ECB_encrypt(xor_strings(extract_keysize_block(plaintext,1,len(key)),iv),key)
	ciphertext += curr_block
	for i in range(1,num_blocks):
		curr_block = AES_ECB_encrypt(xor_strings(extract_keysize_block(plaintext,i + 1,len(key)),
							extract_keysize_block(ciphertext,i,len(key))),key)
		ciphertext += curr_block
	return ciphertext

#Test challenge10.
if (num_set == 2 and num_challenge == 2):
	'''
	In this challenge we will implement AES in CBC(cipher block chain) mode
	of operation by using the AES-ECB code that we wrote earlier.
	We will test our code by decrypting the ciphertext in the file set2challenge2.txt
	'''
	my_file = open("set2challenge2.txt","r")
	content = base64.b64decode(my_file.read())
	#We are given the iv:
	iv = chr(0) * 16
	print(AES_CBC_dec(content,"YELLOW SUBMARINE",iv))

def gen_rand_key(keysize):
	'''
	Generate a random AES key of size keysize.
	Use os.urandom function.Other random psuedorandom generators in python
	aren't known to be cryptographically secure.
	Input:The keysize.
	Output:Completely random key.
	'''
	return os.urandom(keysize)

def encrption_oracle(plaintext):
	'''
	Given some plaintext we will encrypt it under some random generated key,where half the time
	it will be encrypted in ECB mode and the other half it will be encrypted in CBC mode.
	Input:The given plaintext.
	Output:Produced ciphertext.
	'''
	plaintext = os.urandom(random.randint(5,10)) + plaintext + os.urandom(random.randint(5,10))
	plaintext = PKCS7(plaintext,16)
	#Generate key.
	key = gen_rand_key(16)
	#Decide mode of operation.
	if (random.randint(0,1) == 1):
		#Run ECB mode.
		print("Chose ECB")
		ciphertext = AES_ECB_encrypt(plaintext,key)
	else:
		#Run CBC mode.
		print("Chose CBC")
		ciphertext = AES_CBC_enc(plaintext,key,iv = os.urandom(16))
	return ciphertext

def detect_AES_mode(ciphertext,blocksize):
	'''
	Given some ciphertext this function will detect whether the mode of operation was ECB or CBC.
	Note:The assumption is that there are only 2 modes of operation available:ECB or CBC therefore
	detecting ECB is enough.
	'''
	if(detect_AES(ciphertext)):
		return AES.MODE_ECB
	return AES.MODE_CBC

#Test challenge11.
if (num_set == 2 and num_challenge == 3):
	'''
	In challenge11 the goal is to write a function that detects,
	whether the block cipher mode that was used for encryption was ECB or CBC.
	The only flaw that we can use for this challenge is that ECB is stateless,
	i.e. similar blocks of plaintext will be encrypted to similar blocks of ciphertext,
	so the property of similar ciphertext blocks indicates the use of ECB mode of encryption
	(it can't happen in CBC because each ciphertext block is a result of the encryption of xor 
		of current plaintext block and previous ciphertext block)
	We can simply use the function that we wrote to detect AES in ECB mode in the previous exercise.
	'''
	for i in range(10):
		text = "x" * 48
		ciphertext = encrption_oracle(text)
		if (detect_AES_mode(ciphertext,16) == AES.MODE_ECB):
			print("I'm sensing there was use of ECB.")
		else:
			print("I'm sensing CBC is around here.")

#For this challenge the block size is 16 bytes(saving in variable to ignore magic numbers)
BLOCKSIZE = 16
#Global variable for unknown key.
unknown_key = os.urandom(BLOCKSIZE)
unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
					aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
					dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
					YnkK"

def ECB_enc_randkey(plaintext):
	'''
	Encrypt using AES in ECB mode using some unknown key defined above,the function
	will add the unknown string defined above to each plaintext before the encryption.
	'''
	obj = AES.new(unknown_key,AES.MODE_ECB)
	return obj.encrypt(PKCS7(plaintext,16))

def dec_ecb(str_len,num_blocks,check_block = 1,prepend = ""):
	'''
	This function decrypts the ciphertext of the unknown_string variable,by using
	the string length that we calculated and the number of blocks.
	We will decrypt each block seperately by using the one_byte_dec_ecb that decrypts one byte
	at a time of each block,at the end we will have the complete string.
	Input:The unknown string's length and it's number of blocks.
	Output:The complete decrypted string(AWESOME).
	'''
	found = ""
	remainder = str_len % BLOCKSIZE
	#Find block at a time.
	found_block = ""
	prev_block = None
	for i in range(num_blocks - 1):
		#Find whole bytes of block.
		for j in range(BLOCKSIZE):
			found_block += one_byte_dec_ecb(i + check_block,found_block,prev_block,check_block,prepend)
		found += found_block
		#Save current block as the previous block for the next iteration.
		prev_block = found_block
		#Set the block to be empty for the next iteration.
		found_block = ""
	#Find last block(might not be of size BLOCKSIZE)
	#Maybe can save this code if I add an if clause in the loop.
	for i in range(remainder):
		found_block += one_byte_dec_ecb(num_blocks - 1 + check_block,found_block,prev_block,check_block,prepend)
	#Add last block.
	found += found_block
	return found

def one_byte_dec_ecb(numblock,found,prev_block = None,check_block = 1,prepend = ""):
	'''
	Implementation of one at a time decryption of the input ciphertext.
	Input:The number of block that we are decrypting,the bytes found so far in this block,
	and the previous block,if there is no default block it's set by default to None.
	Output:The byte that was found.
	'''
	my_str = 'A' * (BLOCKSIZE - len(found) - 1)
	encrypted = ECB_enc_randkey(prepend + my_str + base64.b64decode(unknown_string))
	for i in range(256):
		#Check if there is a previous block,i.e. if we are at the first block.
		if (prev_block != None):
			curr_enc = ECB_enc_randkey(prepend + prev_block[(len(found) + 1):] + found + chr(i) \
						+ base64.b64decode(unknown_string))
		else:
			curr_enc = ECB_enc_randkey(prepend + my_str + found + chr(i) + base64.b64decode(unknown_string))
		if (extract_keysize_block(encrypted,numblock,BLOCKSIZE) == 
			extract_keysize_block(curr_enc,check_block,BLOCKSIZE)):
			#Found the correct character.
			return chr(i)

def find_target_length(prepend = ""):
	'''
	Used for challenge 12 and 14,finds the length of target string that is added after each plaintext 
	in encryption.
	Input:The string that we need to prepend if needed(for challenge14)
	Output:Length of the target string and it's number of blocks.
	'''
	curr_str = ""
	starting_num_blocks = int(math.ceil(float(len(ECB_enc_randkey(prepend + curr_str \
							+ base64.b64decode(unknown_string)))) / BLOCKSIZE))
	for i in range(BLOCKSIZE):
		curr_str += "A"
		curr_num_blocks = math.ceil(float(len(ECB_enc_randkey(prepend + curr_str\
						+ base64.b64decode(unknown_string)))) / BLOCKSIZE)
		if (curr_num_blocks > starting_num_blocks):
			str_len = starting_num_blocks * BLOCKSIZE - i - len(prepend)
			return str_len,starting_num_blocks

#Test challenge12.
if (num_set == 2 and num_challenge == 4):
	'''
	In this challenge we will implement byte at a time decryption of ECB mode,
	we will use a function(defined above) that encrypts with the same key each time(but
		the key is unknown) and each time the functions adds an unknown string to the plaintext
		before the encryption,we will show that by feeding this function different plaintexts
		we can find the unknown strings.
	'''
	#First we will find out the number of blocks in the cipher(it's size).
	str_len,starting_num_blocks = find_target_length()
	#Now decrypt one byte at a time.
	print"After decryption:%s " % dec_ecb(str_len,starting_num_blocks)

def parser(inp_str):
	'''
	This function is used as a parser that takes input string of a specific format
	and converts it to a JSON format.
	Example:for the input string foo=bar&baz=qux&zap=zazzle we will get the output
	{
	  foo: 'bar',
	  baz: 'qux',
	  zap: 'zazzle'
	}
	'''
	json_lst = []
	#Use try catch block if error thrown for incorrect string.
	try:
		f_split = inp_str.split('&')
		for i in range(len(f_split)):
			curr_split = f_split[i].split('=')
			json_lst.append((curr_split[0],curr_split[1]))
		return json.dumps(OrderedDict(json_lst),indent = 4,separators = (',',': '))
	except (IndexError,ValueError):
		print("String must be of the format key1=val1&key2=val2")
		exit()

#Create global uid variable,it will be incremented for each profile.
uid = 0

def profile_for(email_adr):
	if "&" in email_adr or "=" in email_adr:
		raise ValueError("You cant insert & = characters into the email adress,these characters can't be encoded.")
	else:
		#Make each profile a user role(no admins).
		#uid += 1
		return ("email=" + email_adr + "&uid="  + str(uid) + "&role=user")

#Test challenge13.
if (num_set == 2 and num_challenge == 5):
	'''
	In this challenge we will implement at first two functions, the parser function converts encoded
	strings of a specific format to JSON format,the profile_for function receives an email adress and
	generates an encoded string for this new user.
	Next we will use the ECB_enc_randkey function that we implemented to encrypt an encoded user profile
	under some random key(which is unknown to the attacker) and decrypt the encoded user profile and parse it.
	The attacker is given the user input to profile_for and the ciphertext themselves and the goal is
	to create a profile with role=admin.
	This is the cut and past flaw of ECB block cipher mode,we will use the encryption function(without knowing
		the random key) and encrypt a user email of the type admin@something.com,it doesn't include any &
	or = characters so it's fine.Then we will take the part of the ciphertext that corresponds to "admin"
	and copy and paste to the location of "user" in the given ciphertext,because we always use the same random
	key after decryption and parsing we will get role=admin user.
	'''
	#Some random user input.
	inp_profile = profile_for("liortheking@gmail.com")
	#Generate profile and encrypt it.
	ciphertext = ECB_enc_randkey(inp_profile)
	#Find index of the string user in the inp_string.
	user_index = inp_profile.find("user") % BLOCKSIZE
	required_offset = BLOCKSIZE - user_index
	#We want user to hold it's own block.
	inp_profile = 'A' * required_offset + inp_profile
	ciphertext = ECB_enc_randkey(inp_profile)
	#Num blocks.
	num_blocks = len(ciphertext) / BLOCKSIZE
	#Get block with decryption of admin with correct padding.
	target_block = "admin" + chr(11) * 11
	#Create attacker profile.
	attacker_profile = profile_for('A' * 10 + target_block + "@gmail.com")
	attacker_cipher = ECB_enc_randkey(attacker_profile)
	#Extract target block.
	target_block = extract_keysize_block(attacker_cipher,2,BLOCKSIZE)
	ciphertext = ciphertext[:(num_blocks - 1) * BLOCKSIZE] + target_block
	#Print result.role = admin successfuly.
	print AES_ECB_decrypt(ciphertext,unknown_key)

#Random string of random length (max size is BLOCKSIZE) to prepend before each encryption.
#Note:I chose the max size to be BLOCKSIZE - 1 because if the size is beyond a block we can just
# ignore the first blocks of the random bytes(it doesn't really affect the challenge's difficulty)
random_bytes = os.urandom(random.randint(1,BLOCKSIZE - 1))
def ecb_enc_prepend_rand(plaintext,key):
	'''
	Encrypt plaintext with the given key,prepennd random bytes and append the target string 
	before encryption.
	'''
	obj = AES.new(key,AES.MODE_ECB)
	return obj.encrypt(PKCS7(random_bytes + plaintext + base64.b64decode(unknown_string),BLOCKSIZE))


def one_byte_offset_dec(str_len,numblocks,offset):
	'''
	This function is an upgraded version for the function dec_ecb,(I thought about merging
		those functions but it will result in a scrambled and messy code with lots of if clauses-not fun).
	The difference is that in this function we also get an offset value that tells us the amount of bytes
	that we need to end to the prepended random string so that it fills a full block.
	'''
	pass


#Test challenge14
if (num_set == 2 and num_challenge == 6):
	'''
	This is somewhat of an upgraded challenge to challenge12,
	the goal is the same,decrypt AES in ECB encryption one byte at a time,
	the fact that makes this challenge harder is that not only do we add the target string
	after the plaintext we also prepend a random string of a RANDOM size so we can't use 
	exactly the same strategy that we used the last time.
	The first step to solve this problem is to find out what is the size of the string that
	is prepended in each encryption.
	'''
	#Found out the random string's length.
	prev_block = extract_keysize_block(ecb_enc_prepend_rand("",unknown_key),1,BLOCKSIZE)
	for i in range(BLOCKSIZE):
		curr_block = extract_keysize_block(ecb_enc_prepend_rand("A" * (i + 1),unknown_key),1,BLOCKSIZE)
		if (curr_block == prev_block):
			#Save offset that we need to add.
			offset = i
			break
		prev_block = curr_block
	#Prepended string will be of length BLOCKSIZE
	prepended_str = random_bytes + offset * 'A'
	#Count number of blocks of target.
	str_len,num_blocks = find_target_length(prepended_str)

	print "Decrypted: %s" % dec_ecb(str_len,num_blocks - 1,check_block = 2,prepend = prepended_str)

def PKCS7_validation(text):
	'''
	This function receives some text and checks whether the PKCS7 padding is applied correctly.
	If it isn't applied correctly a ValueError will be raised.
	Input:Some text.
	Output:The same text without the PKCS7 padding.
	'''
	padding_val = ord(text[len(text) - 1])
	if (padding_val > BLOCKSIZE or padding_val == 0):
		#Invalid padding
		raise ValueError("This padding is invalid")
	for i in range(1,padding_val):
		if (text[len(text) - 1 - i] != chr(padding_val)):
			raise ValueError("Invalid PKCS#7 padding.")
	return text[:(len(text) - padding_val)]

#Test challenge15.
if (num_set == 2 and num_challenge == 7):
	'''
	The purpose of this challenge was to simply write the PKCS7_validation function(for later use 
		in padding oracle attack).
	'''
	print PKCS7_validation(PKCS7("Ice cube ",BLOCKSIZE))

prepend_str = "comment1=cooking%20MCs;userdata="
append_str = ";comment2=%20like%20a%20pound%20of%20bacon"

def cbc_enc_prepend_append(plaintext,key,iv):
	'''
	Encrypt with CBC mode where we append and prepend the prepend_str and append_str.
	Input:Plaintext and the key.
	Output:The produced cipher text.
	'''
	#Quote out "=" and ";" characters
	new_plaintext = (prepend_str + plaintext + append_str).replace(";","").replace("=","")
	return AES_CBC_enc(new_plaintext,key,iv)

def admin_verifier(ciphertext,key,iv):
	'''
	This function decrypts the following ciphertext and checks for the 
	presence of the text ";admin=true;"
	'''
	plaintext = AES_CBC_dec(ciphertext,key,iv)
	first_split = plaintext.split(";")
	for i in range(len(first_split)):
		if (first_split[i].find("admin") != -1):
			print("Found:",first_split[i])
			curr_tuple = first_split[i].split("=")
			if (curr_tuple[0] == "admin" and curr_tuple[1] == "true"):
				return True

	return False

def cbc_bitflip_attack(key,iv,target_block):
	'''
	Implementation of CBC bitflipping attack.
	'''
	#First let's compute the number of blocks of the prepended string(I'm assuming the attacker doesn't know
		# the value of the prepended string)
	starting_cipher = cbc_enc_prepend_append("",key,iv)
	starting_num_blocks = int(math.ceil(float(len(starting_cipher)) / BLOCKSIZE))
	for i in range(BLOCKSIZE):
		curr_cipher = cbc_enc_prepend_append('A' * i,key,iv)
		curr_num_blocks = int(math.ceil(float(len(curr_cipher)) / BLOCKSIZE))
		if (curr_num_blocks != starting_num_blocks):
			#Save bytes needed to complete it to a full block.
			offset_needed = i
	offset_str = 'A' * offset_needed
	#Find how much blocks does the prepended string take.
	my_str = 'A' * (offset_needed + BLOCKSIZE)
	#Now find the number of block of the ciphertext Ci with corresponds to 'A' * BLOCKSIZE
	ciphertext = cbc_enc_prepend_append(my_str,key,iv)
	#We know that in CBC Ci = Enc(Pi XOR C(i-1))
	ciphertext_blocks = len(ciphertext) / BLOCKSIZE
	for i in range(1,ciphertext_blocks):
		if (extract_keysize_block(ciphertext,i + 1,BLOCKSIZE) == 
					AES_ECB_encrypt(xor_strings('A' * BLOCKSIZE,
						extract_keysize_block(ciphertext,i,BLOCKSIZE)),key)):
			print("Found num block:",i)
			prepended_blocks = i

	#Now we have all the information needed to perform the attack.
	dec_cipherblock = xor_strings('A' * BLOCKSIZE,
										extract_keysize_block(ciphertext,prepended_blocks,BLOCKSIZE))
	#Set the ciphertext block to fit the target block.
	bitflipped_cipher  = ciphertext[:BLOCKSIZE * (prepended_blocks - 1)] + \
							xor_strings(dec_cipherblock,target_block) + ciphertext[BLOCKSIZE * prepended_blocks:]
	#If the admin verifier returns True that means we are done.
	print admin_verifier(bitflipped_cipher,key,iv)


#Test challenge16.
if (num_set == 2 and num_challenge == 8):
	'''
	In this challenge we will implement the CBC bit flipping attack,we will show that
	we can break the crypto by changing bits of the ciphertext and not knowing anything
	about the key that was used.
	In this attack we are relying on the fact that in CBC mode a 1-bit error in the ciphertext block
	completely scrambles the specific block that the error is in,and creates the same error in the next
	ciphertext block,this happens in this mode because in CBC before we encrypt each plaintext block we are
	doing the XOR operation with the previous ciphertext block that we produced,therefore in the decryption
	we xor each decryption of a ciphertext block(in ECB mode) with the previous ciphertext block.
	'''
	iv = os.urandom(BLOCKSIZE)
	cipher = cbc_enc_prepend_append("admin=true",unknown_key,iv)
	print (admin_verifier(cipher,unknown_key,iv))
	target_block = ";admin=true;" + chr(4) * 4
	cbc_bitflip_attack(unknown_key,iv,target_block)

#Save list of strings.
my_strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
				"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
				"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
				"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
				"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
				"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
				"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
				"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
				"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
				"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]


def enc_string(key):
	'''
	This function will use the unknown_key variable which is a random key that is 
	generated in each execution of the program to encrypt one of the following strings
	in the list my_strings.
	Input:None.
	Output:The ciphertext and the iv that we used.
	'''
	#Generate some random iv.
	iv = os.urandom(BLOCKSIZE)
	#Choose a string randomly.
	chosen_str = base64.b64decode(my_strings[random.randint(0,len(my_strings) - 1)])
	print "Chose the string:%s" % chosen_str
	#Use the encryption in CBC that we wrote.Return ciphertext and the iv.
	return AES_CBC_enc(chosen_str,key,iv),iv

def padding_oracle(ciphertext,key,iv):
	'''
	In this padding_oracle function we will decrypt the following ciphertext using the AES_CBC_dec function 
	that we wrote,than we will use the PKCS7_validation function to check whether the padding that is applied
	to the plaintext that was produced is correct.
	Input:The ciphertext and key and iv that were used during the encryption.
	Output:True if the padding is valid,False otherwise.
	'''
	plaintext = AES_CBC_dec(ciphertext,key,iv)
	#print "Last val:%d" % ord(plaintext[len(plaintext) - 1])
	try:
		no_padding_plaintext = PKCS7_validation(plaintext)
		return True
	except ValueError,IndexError:
		return False

def oracle_attack(ciphertext,key,iv):
	'''
	Implementation of the padding oracle attack. We will find the value of the intermediate state of
	each block at each time and then use it to find the plaintext block.
	Note:We do get the key and iv as inputs (just so we can encrypt and decrypt) but in a real attack on a
	web server the server holds the key and iv,here all the actions performed by the "attacker" don't really
	depend on the value of the key or iv.
	Input:The ciphertext,key and the iv.
	Output:The produces plaintext,with the padding lifted off.
	'''
	num_blocks = len(ciphertext) / BLOCKSIZE
	plaintext = ""
	prev_block = iv
	for i in range(num_blocks):
		target_block = extract_keysize_block(ciphertext,i + 1,BLOCKSIZE)
		curr_intermediate = ""
		calculated_bytes = ""
		for j in range(BLOCKSIZE):
			#Create the edited ciphertext:consists of edited block and the target block that we wish to decrypt.
			prepend = os.urandom(BLOCKSIZE - 1 - j)
			for k in range(256):
				edited_ciphertext = prepend +  chr(k) +\
								calculated_bytes + target_block
				#Test if padding is valid.
				if (padding_oracle(edited_ciphertext,key,iv)):
					#Ij = Pj ^Cj-1,use that calculation and the probability that valid padding gives value of
					#last byte of Pj
					curr_intermediate = chr((j + 1) ^ k) + curr_intermediate
					break
			#Calculate the bytes needed to find next byte.
			calculated_bytes = xor_strings(curr_intermediate,chr(j + 2) * len(curr_intermediate))
		#When full intermediate block is found find plaintext.
		plaintext += xor_strings(curr_intermediate,prev_block)
		prev_block = target_block
	#Return the plaintext without the padding.
	return PKCS7_validation(plaintext)




#Test challenge17.
if (num_set == 3 and num_challenge == 1):
	'''
	Padding oracle attack.
	For deep explanation of how this works see: https://robertheaton.com/2013/07/29/padding-oracle-attack/
	'''
	#Produce a plaintext of some string.
	ciphertext,iv = enc_string(unknown_key)
	print "Result of padding oracle attack: %s" % oracle_attack(ciphertext,unknown_key,iv)

def get_numblocks(plaintext,BLOCKSIZE):
	'''
	Just because it's annoying to write the same line over and OVER AGAIN.
	'''
	return int(math.ceil(float(len(plaintext)) / BLOCKSIZE))


def AES_CTR(plaintext,key,nonce):
	'''
	Implementation of the encryption/decryption process in AES-CTR block cipher mode,this mode
	turns the block cipher AES encryption to a stream cipher,we will use the given nonce and
	increment_counter function to create the key stream.
	Use the struct.pack function to increment the counter(saves some code).
	Note:The format that we will use for the total 16 byte counter is:
		64 bit unsigned little endian nonce(given as input),
		64 bit little endian count(incremented by increment_counter function).
	Inputs:
		- plaintext: The plaintext that we will encrypt.
		- key: The key that will be used in the creation of the keystream.
		- nonce: The value that will be used for the toal counter.
	Output:
		- The produced ciphertext.(or plaintext cause encryption and decryption are the same)
	'''
	counter = struct.pack("<Q",0)
	#Get number of blocks of plaintext.
	num_blocks = get_numblocks(plaintext,BLOCKSIZE)
	ciphertext = ""
	#Produce ciphertext blocks.
	for i in range(num_blocks):
		keystream = AES_ECB_encrypt(key,nonce + counter)
		#Xor keystream with current block.
		ciphertext += xor_strings(extract_keysize_block(plaintext,i + 1,BLOCKSIZE),keystream)
		#Increment counter
		counter = struct.pack("<Q",i + 1)
	return ciphertext


#Test challenge18.
if (num_set == 3 and num_challenge == 2):
	'''
	In this challenge we will implement CTR block cipher mode.(Counter mode)
	CTR mode is an AES block cipher mode that turns AES into a stream cipher.
	Instead of encrypting the plaintext we will encrypt something called a "keystream",
	we will have a "stream" of keys at each block encryption,each plaintet block will be xored 
	with the currently produced keystream,the keystream will be produced by a counter function,for each
	block of the plaintext we will use the counter function and AES encryption to receive the current keystream
	and then xor it with the current plaintext block to receive the ciphertext block.
	Another important property of CTR mode is that it doesn't require any padding.
	Note:The format that I rely on while writing CTR mode is that we are working in a system
	that uses little-endian scheme and the keystream is used both with a counter that is
	incremented and with a nonce.
	'''
	#This is the ciphertext that we are given in the challenge.
	plaintext = "liortheking" * 10
	ciphertext = AES_CTR(plaintext,"YELLOW SUBMARINE",struct.pack("<Q",8))
	print("The ciphertext:",ciphertext)
	print("After decryption:",AES_CTR(ciphertext,"YELLOW SUBMARINE",struct.pack("<Q",8)))


def find_first_byte(ciphertexts):
	'''
	We will use this function to find the first byte of the keystream that was used to encrypt
	the folllowing ciphertexts,we will rely on the fact that in english sentences begin with a capital letter.
	Input:
		- ciphertexts: A list of the ciphertexts that were produced with the keystream.
	Output:
		- The byte that creates plaintexts that begin with a capital letter.
	'''
	buff = os.urandom(15)
	for i in range(256):
		keystream = chr(i) + buff
		valid = True
		for j in range(len(ciphertexts)):
			result = xor_strings(ciphertexts[j],keystream)
			#Check for capital letter.
			if (not (ord(result[0]) >=65 and ord(result[0]) <= 90)):
				#Set bool variable
				valid = False
		if (valid):
			#Meaning that the result was that all plaintexts started with a capital letter.
			first_byte = i
			return i

def find_byte(ciphertexts,found,curr_keys):
	'''
	In this function we will find one byte of the keystream by using the previous bytes that we found and a
	list of english phrases that have a high probability to appear in the plaintexts(these are guesses that
		were produced by checking out the input of the letters of the plaintexts that we found out so far).
	Inputs:
		- ciphertexts: The list of ciphertexts that were produced by using the same keystream.
		- found: The bytes of the keystream that were found so far.
		- curr_keys: The phrases that we expect to show up in the plaintexts with high probability.
	Output:
		- The byte that got the highest score based on the scoring system that we created with curr_keys.
	'''
	max_score = 0
	for i in range(256):
		score = 0
		keystream = found + chr(i)
		for j in range(len(ciphertexts)):
			result = xor_strings(keystream,ciphertexts[j])
			if (result in curr_keys):
				score += 1

		#Check the score.
		if (score > max_score):
			max_score = score
			found_byte = i
	#Return max result.
	return found_byte

#Test challenge19.
if (num_set == 3 and num_challenge == 3):
	'''
	Break Fixed-nonce CTR mode using substitutions.
	We will use the encrypt and decrypt functions of AES in CTR mode that we wrote earlier with a nonce
	set to 0.
	In the file set3challenge3.txt there is a list of base64 encoded plaintexts,we will encrypt all of them
	one by one and get a list of ciphertexts.
	The flaw in this way of CTR encrpytion is that the nonce was FIXED.The nonce wasn't randomized so we
	encrypted all of the plaintext with the SAME KEYSTREAM.
	Now we know that after the calculation of the keystream during the encryption,the stream cipher operation
	boils down to a simple xor operation with the plaintext block,so once we found the key stream we can
	find the whole plaintext.
	We will find the keystream by using several english statistics and a scoring system for english texts
	on the produces ciphertexts for each key stream that we guess.
	Note:We will use a random AES key(here it's the variable unknown_key) for the encryption process.
	'''
	my_file = file("set3challenge3.txt","r")
	#Read plaintexts.
	plaintexts = [curr_str.replace("\n","") for curr_str in my_file.readlines()]
	ciphertexts = []
	fixed_nonce = struct.pack("<Q",8)
	#Compute all the ciphertexts.
	for i in range(len(plaintexts)):
		ciphertexts.append(AES_CTR(base64.b64decode(plaintexts[i]),unknown_key,fixed_nonce))

	'''
	We will crack the keystream blocks one step at a time.
	Each block is 16 bytes,which takes up to (2^8)^16 options,it is unfeasible to go
	over all of them.
	First step:Find the first byte of the key stream by find the byte that leads to
	that all the plaintexts start with a capital letter.
	Second step:Use digraphs statistics to find the second letter.
	Continue for each letter. (There are 30+ letters so because it's not automated it can be
		a bit painful)
	Note: This is code is NOT automated,the way the combinations of letters of each length was built
	is by looking at the decrypted info that we got and guessing the next fitting letter,for example:
	if after decrypting 3 bytes we get the combination "Wha" a valid guess would be that the next letter
	would be 't' and we would receive "What".
	'''

	keystream = chr(find_first_byte(ciphertexts))
	#Find second byte.
	digraphs = [digraph.title() for digraph in common_digraphs.keys()]
	#Add some digraphs.
	digraphs += ['Of','So','Or','To','He','In','Wa','A ','I ','Po','Be','Ar']
	trigraphs = [trigraph.title() for trigraph in common_trigraphs.keys()]
	trigraphs += ['And','Thi','Com','But','All','She','Yet','Wha','Whe']
	four_letter_combos = ["What","This","When","Unti","From",'Comi','Bein',]
	five_letter_combos = ["Until","Being","Around","Comin","I hav"]
	six_letter_combos = ["I have","Coming"]
	seven_letter_combos = ["Eightee","A terri"]
	eight_letter_combos = ["Eighteen","He might","Transfor","He might"]
	nine_letter_combos = ["A terribl","Eighteent","Transform"]
	ten_letter_combos = ["A terrible","Eighteenth","Transforme","What voice","Until her "]
	eleven_letters = ["Coming with","Eighteenth-","I have pass"]
	twelve_letters = ["Yet I number"]
	thirteen_letters = ["In the casual","He might have"]
	fourteen_letters = ["Until her voic"]
	fifteen_letters = ["Until her voice","I have met them"]
	sixteen_letters = ["A terrible beaut"]
	seventeen_letters = ["Coming with vivid","A terrible beauty"]
	eighteen_letters = ["Eighteenth-century"]
	nineteen_letters = ["So daring and sweet"]
	twenty_letters = ["Or polite meaningles"]
	twentyone_letters = ["Or polite meaningless","He, too, has resigned"]
	twentytwo_letters = ["When young and beautif"]
	twentythree_letters = ["When young and beautifu"]
	twentyfour_letters = ["When young and beautiful"]
	twentyfive_letters = ["And rode our winged horse"]
	twentysix_letters = ["From counter or desk among"]
	twentyseven_letters = ["He had done most bitter wro"]
	twentyeight_letters = ["This other man I had dreamed"]
	twentynine = ["He had done most bitter wrong"]
	thirty = ["So sensitive his nature seemed"]
	thirtyone = ["I have passed with a nod of the"]
	thirtytwo = ["Or have lingered awhile and said"]
	thirtythree = ["He might have won fame in the end"]
	thirtyfour = ["I have passed with a nod of the he"]
	thirtyfive = ["I have passed with a nod of the hea"]
	thirtysix = ["I have passed with a nod of the head"]
	thirtyseven = ["He, too, has been changed in his turn"]
	thirtyeight = ["He, too, has been changed in his turn."]
	combos = [digraphs,trigraphs,four_letter_combos,five_letter_combos,six_letter_combos,seven_letter_combos\
					,eight_letter_combos,nine_letter_combos,ten_letter_combos,eleven_letters,twelve_letters\
					,thirteen_letters,fourteen_letters,fifteen_letters,sixteen_letters,seventeen_letters\
					,eighteen_letters,nineteen_letters,twenty_letters,twentyone_letters,twentytwo_letters\
					,twentythree_letters,twentyfour_letters,twentyfive_letters,twentysix_letters,\
						twentyseven_letters,twentyeight_letters,twentynine,thirty,thirtyone,thirtytwo\
						,thirtythree,thirtyfour,thirtyfive,thirtysix,thirtyseven,thirtyeight]
					
	for i in range(1,len(combos) + 1):
		keystream += chr(find_byte(ciphertexts,keystream,combos[i - 1]))
	#Review results.
	print "Printing substitution attack results"
	for i in range(len(ciphertexts)):
		result = xor_strings(ciphertexts[i],keystream)
		print "Ciphertext length:%d result length:%d" % (len(ciphertexts[i]),len(result))
		print "Result:%d String: %s" % (i,result)
	#Print the plaintexts for comparison.
	print "Printing plaintexts"
	for i in range(len(plaintexts)):
		print "Num: %d Plaintext:%s" % (i,base64.b64decode(plaintexts[i]))

#Test challenge20.
if (num_set == 3 and num_challenge == 4):
	'''
	Break fixed-nonce CTR with statistics.
	'''
	my_file = file("set3challenge4.txt","r")
	plaintexts = [curr_str.replace("\n","") for curr_str in my_file.readlines()]
	ciphertexts = []
	smallest_length = sys.maxint
	for i in range(len(plaintexts)):
		curr_cipher = AES_CTR(base64.b64decode(plaintexts[i]),unknown_key,struct.pack("<Q",8))
		ciphertexts.append(curr_cipher)
		if (len(curr_cipher) < smallest_length):
			smallest_length = len(curr_cipher)

	#Now use the smallest length to truncate all ciphertexts.
	#Strings are immutable in python so we will have to create a new string.
	final_str = ""
	for i in range(len(ciphertexts)):
		final_str += ciphertexts[i][:smallest_length]

	#Now break as repeating key xor.Same as challenge 6.
	key = break_repeating_xor(final_str,smallest_length)
	print("Produced ciphertexts:",repeating_xor_key(final_str,key))
	#After this is solved there is not much more work left to do.


def _int32(num):
	'''
	This function will return the 32 least significant bits of the number given in
	the input,converting it to a 32 bit integer.
	Input:
		- num: The number that will be converted.
	Output:
		- The 32 LSB's of this number.
	'''
	return (0xffffffff & num)

class MT19937:

	'''
	In this class we will implement the algorithm for the mersenne twister 19937 PRNG.
	The code of the algorithm was written by using the algorithm description from
	wikipedia: https://en.wikipedia.org/wiki/Mersenne_Twister.
	'''
	def __init__(self,seed,internal_state = None):
		'''
		Constructor of the MT19937 class.
		Inputs:
			- seed: The seed we will use for the generator.
			- internal_state: In the case we will create a "spliced" generator.
		'''
		#Initialize the index to 0.
		self.index = 0
		#Initialize the state vector.
		if internal_state == None:
			self.mt = [0] * 624
			#Initial state will be the input seed.
			self.mt[0] = seed
			for i in range(1,624):
				self.mt[i] = _int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)
		else:
			self.mt = internal_state
			self.index = len(internal_state)

	#This is also called the temper function.
	def extract_number(self):
		#Check if index passed the state vector's length.
		if self.index >= 624:
			self.twist()

		# Extract current state.
		y = self.mt[self.index]

		# Right shift by 11 bits.
		y ^= (y >> 1)
		# Shift y left by 7 and take the bitwise and of 2636928640
		y ^= (y << 7) & 2636928640
		# Shift y left by 15 and take the bitwise and of y and 4022730752
		y ^= (y << 15) & 4022730752
		# Right shift by 18 bits.
		y ^= (y >> 18)

		#Increment the index.
		self.index = self.index + 1

		return _int32(y)

	def twist(self):
		for i in range(624):
			#Get the most significant bit and add it to the least significant bits of the next number.
			y = _int32((self.mt[i] & 0x80000000) + \
							(self.mt[(i + 1) % 624] & 0x7fffffff))
			self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

			if y % 2 != 0:
				self.mt[i] = self.mt[i] ^ 0x9908b0df

			#Initialize index back to 0.
			self.index = 0

#Test challenge21.
if (num_set == 3 and num_challenge == 5):
	'''
	Implement the MT19937 Mersene twister RNG(random number generator).
	We will next show that this PRNG is not cryptographically secure.
	Here we will just test the MT19937 class(given a specific seed we will get the same sequence.)
	'''
	seed = 20
	prng = MT19937(seed)
	for i in range(20):
		print "Current number: %d" % prng.extract_number()


#Test challenge22.
if (num_set == 3 and num_challenge == 6):
	'''
	Crack the MT19937 seed,we will proof that this PRNG is not cryptographically secure.
	We will write a routine that will:
		- Wait a random number of seconds at first (so the seed will be completely random at each execution)
		- Get the current UNIX timestamp and use it as a seed for the RNG.
		- Wait another random number of seconds.
		- Output the first 32 bit integer extracted from the RNG.

	This exercise emphasizes the fact that the seed dictates the whole sequence of integers that
	are extracted from the RNG.
	This is more of a timing attack than a real attack on the RNG.(the next challenge will introduce
		a real way of attacking the RNG's algorithm)
	Note: We will simulate the waiting time,to save time.
	'''
	seed = int(time.time()) + random.randint(40,1000)
	print "Chose seed: %d" % seed
	rng = MT19937(seed)
	extracted_num = rng.extract_number()
	curr_time = seed + random.randint(40,1000)
	#Find the seed.
	for i in range(curr_time - 1001,curr_time):
		if MT19937(i).extract_number() == extracted_num:
			print "Found the seed: %d" % i

def untemper(num):
	'''
	This function receives the first number extracted from a MT19937 RNG and does 
	the reverse operations of the MT19937.extract_number() function to receive the seed 
	of the RNG. We will use this for challenge 7 of set 3.
	We need to apply the reverse of two operations: shift and xor.
	The reverse of xor is obvious because xor is a symmetric operation.
	On the otherhand the case of shift is a little more complicated.
	We will notice that for integers shift is not completely invertible because if we divide a
	number by some power of two we will lose information(it may be odd or even) so for each use
	of shift right there are 2 options we will have to go through while reversing it.
	Input:
		- num: The first 32 bit integer extracted from the RNG.
	Output:
		- The preceding number in the internal state(or some options).
	'''
	#Note:At first I will write the function as simple as possible to ignore bugs as much as I can
	#later I will fix the code in order to save some lines and computations.
	#Computations are a bit complicated.
	#Extract all 3 parts.
	first_part = ((2 ** 14 - 1) << 18) & num
	second_part = ((2 ** 4 - 1) << 14) & num
	third_part = (2 ** 14 - 1) & num
	a1 = first_part
	lsb_a2 = (a1 >> 18) ^ third_part
	y = (a1 | second_part) | lsb_a2
	#return _int32(y)
	
	#print "After first phase:%d" % y
	

	#Now invert: y ^= (y << 15) & 4022730752'
	first_part = ((2 ** 15 - 1) << 17) & y
	second_part = ((2 ** 2 - 1) << 15) & y
	third_part = (2 ** 15 - 1) & y

	#Compute part of b2.
	part_b2 = (third_part << 15) & 4022730752
	#Get two last bits of part_b2.
	lsb_b2 = ((2 ** 2 - 1) << 15) & part_b2
	msb_a2 = second_part ^ lsb_b2
	a2 = msb_a2 | third_part
	#Get full b2.
	b2 = (a2 << 15) & 4022730752
	a1 = first_part ^ (b2 & ((2 ** 15 - 1) << 17))
	y = a1 | a2
	#print "After second phase: %d" % y

	#Now invert y ^= (y << 7) & 2636928640
	#This one is going to be a bit more complex so I added a few lines of code
	# in hope that it will make it more readable.(The code is based on hand written computations)
	first_part = ((2 ** 7 -1) << 25) & y
	second_part = ((2 ** 18 - 1) << 7) & y
	third_part = (2 ** 7 - 1) & y

	#Get last 7 bits of b2.
	lsb_7_b2 = (third_part << 7) & 2636928640
	#Get another 7 bits of a2 to get total last 14 bits of a2.
	lsb_14_a2 = (second_part ^ lsb_7_b2) | third_part

	#Now get last 14 bits of b2.
	lsb_14_b2 = (lsb_14_a2 << 7) & 2636928640
	lsb_21_a2 = (second_part ^ lsb_14_b2) | third_part
	#Get last 21 bits of b2.
	lsb_21_b2 = (lsb_21_a2 << 7) & 2636928640

	#Get a2 completely.
	a2 = (second_part ^ (((2 ** 18 - 1) << 7) & lsb_21_b2)) | third_part
	b2 = (a2 << 7) & 2636928640
	a1 = first_part ^ (((2 ** 7 - 1) << 25) & b2)
	y = a1 | a2
	#print "After third step:%d" % y

	#Last part will be to invert y ^= (y >> 1)
	msb_a1 = (2 ** 31) & y
	second_part = ((2 ** 30 - 1) << 1) & y
	third_part = 1 & y

	a1 = msb_a1
	#Figure iteratively a1.Go through each bit of the result of second_part
	for i in range(30):
		a1 |= (second_part ^ ((a1 & (2 **(31 - i))) >> 1)) & (2 ** (30 - i))

	#Extract a2.
	a2 = third_part ^ ((a1 & 2) >> 1)
	y = a1 | a2
	return y



#Test challenge23.
if (num_set == 3 and num_challenge == 7):
	'''
	Clone an MT19937 RNG from its output.
	Now this is a challenge with more action.
	The MT19937 RNG holds an internal state of 624 integers, the key of this attack is knowing
	that the temper function used in extract_number is invertible(not completely because of 
	the fact that we shift integers), we will write an untemper function that reverses the
	temper function's operations. We will use this function to receive the full internal state
	of the RNG and create a clone of it.
	This attack can be prevented if we use some kind of one-way function before extracting a number
	from the RNG like a cryptographic hash function.
	'''
	'''y = _int32(24253333522221)
	print "Chose %d" % y
	y ^= (y >> 1)
	print "Now: %d" % y
	y ^= ((y << 7) & 2636928640)
	print "After first step: %d" % y
	y ^= ((y << 15) & 4022730752)
	print "After second step value: %d" % y
	y ^=(y >> 18)
	print "Got   %d" % untemper(y)'''
	#Create a new MT199937 extract 624 outputs and use the untemper function to clone it.
	rng = MT19937(50)
	outputs = []
	for i in range(624):
		outputs.append(rng.extract_number())

	#Use untemper function.
	initial_state = []
	for i in range(623,-1,-1):
		initial_state = [untemper(outputs[i])] + initial_state

	#Create "spliced" MT19937,when it is spliced the seed doesn't matter
	cloned = MT19937(0,internal_state = initial_state) 
	#Now check if we get the exact same numbers.
	for i in range(100):
		print "Original RNG extracted: %d" % rng.extract_number()
		print "Clone extracted: 	   %d" % cloned.extract_number()



def mt19937_stream_cipher(plaintext,seed):
	'''
	This function receives a plaintext and a 16 bit seed to create a keystream using
	a MT19937 PRNG that will be used to create the ciphertext.
	We will note that the output of the PRNG is a 32 bit integer,we will convert it to 4
	characters in order to use the xor_strings function that we already wrote.
	Inputs:
		- plaintext: The text that will be encrypted.
		- seed: 16 bit seed that will be used to create the PRNG.
	Output:
		- The produced ciphertext.
	'''
	#Take only 16 bits of the given seed.
	rng = MT19937(seed & 0xffff)
	num_blocks = int(math.ceil(float(len(plaintext)) / 4))
	#Create the keystream.
	keystream = ""
	for i in range(num_blocks):
		produced_num = rng.extract_number()
		#Use struct module to convert integer to string.
		keystream += struct.pack("<L",produced_num)
	return xor_strings(plaintext,keystream)

def test_password_token(token):
	'''
	Given some password reset token we will check if it was created using a PRNG seeded with the current
	time,we will take a range eps before and after the time and check the products of all the prng's seeded
	with these seeds.
	We will assume the token is the first result extracted from the temper function of the PRNG,
	otherwise it can be the 1000 extracted number from a prng and it will take a lot longer to discover
	if the seed that was used is the current time.
	Inputs:
		- token: Some password reset token.
	Outputs:
		- True if the token is the result of PRNG seeded with current time,false otherwise.
	'''
	curr_time = int(time.time())
	#Choose some random eps.
	eps = 100
	for i in range(curr_time - eps,curr_time + eps + 1):
		curr_prng = MT19937(int(i))
		#Extract a number and
		if (curr_prng.extract_number() == token):
			return True
	return False

#Test challenge24.
if (num_set == 3 and num_challenge == 8):
	'''
	Create the MT19937 stream cipher and break it.
	Turns out we can create a trivial stream cipher from any PRNG, we will just take the outputs of
	the PRNG and use it as a keystream(in our case 32 bit outputs).
	After writing the stream cipher function we will use it to encrypt a known plaintext with a 
	random number of random byted prefixed to it.
	Our goal will be to recover the seed from the ciphertext.
	The important thing we will have to notice is that the seed contains ONLY 16 bits, therefore
	the space of all possible seeds is quite small,because part of the plaintext is known we can
	extract a block of the keystream(which is a number extracted from the PRNG).
	'''
	#Test the stream cipher.
	plaintext = os.urandom(random.randint(1,100)) + 'A' * 14
	seed = ord(os.urandom(1))
	print "Secret seed chosen: %d" % seed
	ciphertext = mt19937_stream_cipher(plaintext,seed)
	#Count number of 4 byte blocks.
	num_full_blocks = len(ciphertext) / 4
	#Find last block of the keystream.
	keystream = xor_strings(extract_keysize_block(ciphertext,num_full_blocks,4),
							'A' * 4)
	#Convert the keystream string back to a number.
	keystream = struct.unpack("<L",keystream)[0]
	print keystream
	#Go over each possible seed and stop when we get to the seed that produces the same keystream.
	for i in range(2 ** 16):
		#Create a new MT19937 PRNG with the current seed.
		curr_prng = MT19937(i)
		for j in range(num_full_blocks):
			num = curr_prng.extract_number()
		#Compare to the number that we got.
		if (num == keystream):
			print "Found it %d" % i
			break

	'''
	We will use the same idea to generate a "password reset token" using MT19937 seeded from the current time
	and we will write a function that given some password token checks if it was created with a MT19937 PRNG 
	seeded with the current time.
	'''
	#Test
	print "Seed a MT19937 PRNG with the current time"
	print "Function says: " + str(test_password_token(MT19937(int(time.time())).extract_number()))
	print "Now testing for some random seed"
	print "Function says: " + str(test_password_token(MT19937(ord(os.urandom(1))).extract_number()))

#We will use a fixed nonce for the following challenge.(randomly we chose 0.)
nonce = struct.pack("<Q",8)

def edit_cipher(ciphertext,key,offset,newtext):
	'''
	This function will receive a ciphertext that was produced using a AES CTR encryption,a key
	and some offset and will seek into the ciphertext to this offset and replace it with the encryption 
	of newtext produced in the input.
	Inputs:
		- ciphertext: The cipher that was produced from AES CTR encryption.
		- key: The key that was used while encrypting(unknown to attacker)
		- offset: The offset we will seek to.
		- newtext: The text we will use to edit the ciphertext.
	Output:
		- new edited ciphertext based on the given newtext and the offset.
	'''
	if (offset >= len(ciphertext)):
		raise ValueError("Offset is out of bounds in edit_cipher")
	#There is no reason to edit the ciphertext to be longer,it doesn't help us get any additional information.
	if (offset + len(newtext) > len(ciphertext)):
		raise ValueError("newtext given is too long in edit_cipher")
	#Decrypt the ciphertext.
	plaintext = AES_CTR(ciphertext,key,nonce)
	#Change the text to newtext at the given offset.
	edited_plaintext = plaintext[:offset] + newtext
	#Test if the newtext covers the rest of the ciphertext length.
	if (offset + len(newtext) < len(ciphertext)):
		edited_plaintext += plaintext[offset + len(newtext):]
	#Encrypt after getting the original plaintext edited.
	return AES_CTR(edited_plaintext,key,nonce)

#Test challenge25.
if (num_set == 4 and num_challenge == 1):
	'''
	Break random access read/write AES CTR.
	In this challenge we will check out another weakness of AES in CTR mode,notice that not like
	the case of CBC encryption,in CTR mode we can acces the Nth byte of the ciphertext by only 
	have the Nth byte of the keystream.
	In this scenario we will assume the attacker can use some sort of API that gives him the option
	to edit the ciphertext at some given offset without knowing the original plaintext or the key.
	By using this API the attacker can simply guess each byte of the plaintext by editing each character
	in the plaintext and check which value of newtext produces the same value of ciphertext that he got
	in the first place.
	Note: This solution might seem a bit slow but the time it takes is bearable(about 10 minutes) so you
	can go ahead and make a good cup of coffee until it's done.
	'''
	my_file = file("set4challenge1.txt","r")
	#Read all the plaintexts.	
	plaintext = AES_ECB_decrypt(base64.b64decode(my_file.read()),"YELLOW SUBMARINE")
	#We will use the random key saved in unknown_key variable.
	ciphertext = AES_CTR(plaintext,unknown_key,nonce)
	found_plaintext = ""
	#Now the attacker will discover one byte at a time using the edit function.
	for i in range(len(plaintext)):
		#Check all byte values.
		for guess in range(256):
			edited_ciphertext = edit_cipher(ciphertext,unknown_key,i,chr(guess))
			if (edited_ciphertext == ciphertext):
				#Means we found one byte of the plaintext.
				found_plaintext += chr(guess)
				break
		print "Found so far %s" % found_plaintext
	print "Found plaintext: %s" % found_plaintext

def prefix_suffix_ctr(plaintext,key,nonce):
	'''
	Encrypt under CTR mode using the given plaintext,key and nonce, we will prefix 
	and suffix specific strings to each plaintext that is given in the input before encryption.
	This is simply one line of code but this makes the code more readable.
	Same as challenge16 we will prevent using ; and = characters in the plaintext.
	'''
	return AES_CTR(prepend_str + plaintext.replace("=","").replace(";","") + append_str,key,nonce)

def ctr_bitflip_attack(key,nonce,target_block):
	'''
	This function performs a bitflip attack on ctr mode.
	It will be pretty similar to the way we attacked cbc mode.
	We will find out the number of 16 byte blocks produced by the prefix and suffix
	strings,we will use the fact that as an attacker we know of the prefix and suffix strings.
	'''
	#If target block contains ; = characters,we know that these character are filtered.
	#We will replace these characters with out own character and use the edit function that we wrote earlier.
	offsets = {}
	prefix_len = len(prepend_str)
	for i in range(len(target_block)):
		#I already wrote code to find the length of prefix string(nothing special).
		#In order to save some lines of code that isn't the main aspect of this challenge 
		#we will assume we have this length and we will add it to the offsets.
		if (target_block[i] == '='):
			offsets[i + prefix_len] = '='
			target_block = target_block[:i] + chr(0) + target_block[i + 1 :]
		elif (target_block[i] == ';'):
			offsets[i + prefix_len] = ';'
			target_block = target_block[:i] + chr(0) + target_block[i + 1:]
	#Now simply use the edit function.
	curr_cipher = prefix_suffix_ctr(target_block,key,nonce)
	for offset,char in offsets.iteritems():
		curr_cipher = edit_cipher(curr_cipher,key,offset,char)
	#Check out the result to see if admin = true slipped in there.
	print AES_CTR(curr_cipher,key,nonce)


#Test challenge26.
if (num_set == 4 and num_challenge == 2):
	'''
	CTR bitflipping.
	We will reimplement the attack we performed on CBC mode in challenge16 to show that
	CTR is vulnerable to bitflipping attacks as well.
	'''
	#16 byte target block.
	target_block = ";admin=true;" + 'A' * 4
	ctr_bitflip_attack(unknown_key,nonce,target_block)