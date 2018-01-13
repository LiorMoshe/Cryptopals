import base64
from Crypto.Cipher import AES
import math
import os
import json
import sys
import random
import struct
import web
import time
from MT19937 import *
from sha1 import sha1
from md4 import *
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

def is_ascii(string):
	'''
	Validates ascii compliance for given input string.
	Input:
		- Some string.
	Output:
		- True if it is ascii encoded,false otherwise.
	'''
	try:
		string.decode("ascii")
	except UnicodeDecodeError:
		return False
	else:
		return True


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
		for i in range(num_blocks,1,-1):
			current_ciphertext_block = extract_keysize_block(ciphertext,i,len(key))
			curr_block = xor_strings(AES_ECB_decrypt(current_ciphertext_block,key),
								extract_keysize_block(ciphertext,i - 1,len(key)))
			plaintext = curr_block + plaintext
	#For the last block we will use the IV.
	curr_block = xor_strings(AES_ECB_decrypt(extract_keysize_block(ciphertext,1,len(key)),key),iv)
	return (curr_block + plaintext)

def AES_CBC_enc(plaintext,key,iv,check_encoding = False):
	'''
	Implementation of encryption process of AES in CBC mode.
	We will use the function that we wrote for AES encryption in AES mode.
	We will add additional code that checks if the given plaintext has ascii compliance,if
	it doesn't we will raise an exception.
	The check_encoding input value tells us if there is any need to check the plaintext's encoding
	(in the challenges later we may be asked to validate ascii encoding.)
	Input:plaintext,the key and the iv that we will use.
	Output:The ciphertext.
	'''
	if (check_encoding and not is_ascii(plaintext)):
		raise ValueError("Plaintext in AES_ECB_enc is not ascii encoded")
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

#The strings we will prepend and append in this challenge.
prepend_str = "comment1=cooking%20MCs;userdata="
append_str = ";comment2=%20like%20a%20pound%20of%20bacon"

def cbc_enc_prepend_append(plaintext,key,iv,iv_as_key = False):
	'''
	Encrypt with CBC mode where we append and prepend the prepend_str and append_str.
	Input:Plaintext and the key and the iv,the iv_as_key indicates if iv and key will be equal or not.
	Output:The produced cipher text.
	'''
	#Quote out "=" and ";" characters
	if (iv_as_key):
		iv = key
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

#Challenge28.Read sha1 secret key from usr/share/dict/words
def sha1_secret_mac(message,key):
	'''
	Implement a SHA-1 keyed MAC.
	Information about the SHA1 algorithm: https://tools.ietf.org/html/rfc3174
	The implementation of the SHA1 algorithm was taken from: https://github.com/ajalt/python-sha1
	This is used for message authentication,if one bit of data changes in the message
	the hash returned from the SHA1 algorithm completely changed,this is the so called
	avalanche effect.
	'''
	return sha1(key + message)

def verify_mac(func,message,mac,key):
	'''
	This will be the function that is ran over a user when we wish to
	authenticate a message given the message and the produced mac.
	Inputs:
		- message: The message that the MAC was produced for.
		- mac: Authentication code that helps the user to validate the message.
		- key: secret prefix key that was agreed upon before the connection.
	Output:
		- True if it's valid,false otherwise.
	'''
	return (mac == func(key + message))

def hmac(hash_function,key,data,block_size):
	'''
	The HMAC algorithm.
	https://tools.ietf.org/html/rfc2104
	Inputs:
		- hash_function: The iterative hash function that this hmac will use.
		- key: The secret key,
		- data: The data that will be hashed.
		- block_size: The blocks that the iterative hash_function iterates through
					  and operates the compression function on.
	'''
	#Define the constants ipad and opad based on the block size used in hash_function
	print "Here in hmac like a boss"
	ipad = chr(0x36) * block_size
	opad = chr(0x5c) * block_size

	#Keys longer than block size will be shortened by hashing.
	if (len(key) > block_size):
		key = hash_function(key)

	#Padd the key to size block_size with 0 padding.
	if (len(key) < block_size):
		key += chr(0) * (block_size - len(key))
	return hash_function(xor_strings(key,opad) + hash_function(xor_strings(key,ipad) + data))

