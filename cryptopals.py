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
	'VE':1/27
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
	if (num_block * keysize > len(text)):
		raise ValueError("num_block is too high in extract_keysize_block")
	return text[(num_block - 1) * keysize: num_block * keysize]



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
	for i in range(num_blocks,0,-1):
		curr_block = xor_strings(AES_ECB_decrypt(extract_keysize_block(ciphertext,i,len(key)),key),
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
	if (padding_val > BLOCKSIZE):
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
	print len(plaintext)
	try:
		no_padding_plaintext = PKCS7_validation(plaintext)
		return True
	except ValueError,IndexError:
		return False

def oracle_attack(ciphertext,key,iv):
	'''
	Implementation of the padding oracle attack. We will find the value of the intermediate state of
	each block at each time and then use it to find the plaintext block.
	'''
	num_blocks = len(ciphertext) / BLOCKSIZE
	plaintext = ""
	prev_block = iv
	for i in range(num_blocks):
		print "Current: %d ciphertext length:%d" % (i,len(ciphertext))
		target_block = extract_keysize_block(ciphertext,i + 1,BLOCKSIZE)
		curr_intermediate = ""
		calculated_bytes = ""
		for j in range(BLOCKSIZE):
			#Create the edited ciphertext:consists of edited block and the target block that we wish to decrypt.
			print "Current j:%d" % j
			for k in range(256):
				#print "Calculated bytes length:%d" % len(calculated_bytes)
				edited_ciphertext = os.urandom(BLOCKSIZE - 1 - j) +  chr(k) +\
								calculated_bytes + target_block
				#print "Length of edited ciphertext:%d" % len(edited_ciphertext)
				#Test if padding is valid.
				if (padding_oracle(edited_ciphertext,key,iv)):
					#Ij = Pj ^Cj-1,use that calculation and the probability that valid padding gives value of
					#last byte of Pj
					curr_intermediate = chr((j + 1) ^ k) + curr_intermediate
					print("CURRENT INTERMEDIATE:",len(curr_intermediate))
					break
			#Calculate the bytes needed to find next byte.
			calculated_bytes = xor_strings(curr_intermediate,chr(j + 2) * len(curr_intermediate))
		#When full intermediate block is found find plaintext.
		plaintext += xor_strings(curr_intermediate,prev_block)
		print "Current plaintext:%s" % plaintext
		prev_block = target_block





#Test challenge17.
if (num_set == 3 and num_challenge == 1):
	'''
	Padding oracle attack.
	For deep explanation of how this works see: https://robertheaton.com/2013/07/29/padding-oracle-attack/
	'''
	my_iv = os.urandom(16)
	ciph = AES_CBC_enc("liorliorliorli",unknown_key,my_iv)
	print "Decryption:%s" % AES_CBC_dec(ciph,unknown_key,my_iv)
	print "Cipher:%s" % ciph
	print padding_oracle(ciph,unknown_key,my_iv)
	ciphertext,iv = enc_string(unknown_key)
	print "The ciphertext: %s" % ciphertext
	oracle_attack(ciphertext,unknown_key,iv)