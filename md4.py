'''
My own implementation of MD4(meanwhile I finally found a good implementation
	online so maybe I will use it instead).
Lior Moshe.2017.
'''
import struct
def circular_left_rotate(x,n):
	'''
	Circular left rotate of a number.
	'''
	return ((x << n) & 0xffffffff) | (x >> (32 - n))

#Define the 3 auxiliary functions used in the RFC.
def F(x,y,z):
	return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
	return x ^ y ^ z


def sha1_padding(message):
	'''
	Generates the needed padding for a given sha1 message.
	We will assume the message length can be written using 2 words(8 bytes).
	Note: We will use big endian format while packing the message length 
	to not differentiate from the implementation in sha1.py.
	Note:This is the same padding that is used for MD4.
	Input:
		- The message we will use sha1 to authenticate.
	Output:
		- String of padding.
	'''
	#Check if message can be divides to 64 byte blocks.If so there is no padding
	if (len(message) % 64 == 0 and len(message) > 0):
		return ""
	#Remember we need to save 2 bytes for the string length.
	#Append message to 64 bytes.We multiply the length by 8 because we need to
	# interpret the BIT length and not the BYTE length.
	padding = b'\x80' + b'\x00' * ((56 - (len(message) + 1) %64) % 64) + \
				struct.pack(b'>Q',(len(message) * 8))
	return padding

def general_round(h,X,func,s_vals,k_update_rule,constant = 0):
	'''
	General function for one round of md4.
	'''
	for j in range(16):
		register_index = (16 - j) % 4
		#Take s from given s_vals.
		s = s_vals[j % 4]
		#Update k based on update rule
		k = k_update_rule(j)
		#Update the internal value h.
		h[register_index] = circular_left_rotate(
									(h[register_index] + func(h[(register_index + 1) % 4],
															 h[(register_index + 2) % 4],
															 h[(register_index + 3) % 4]
															) + X[k] + constant) % 2 ** 32
												,s)
	return h


class MD4(object):
	'''
	In this class we will implement the full MD4 algorithm.
	'''
	def __init__(self,registers = None,message_byte_length = 0):
		'''
		Constructor of MD4 class.
		'''
		#Set registers to initialization values.
		if (registers == None):
			self._h = [0x67452301,
	                0xefcdab89,
	                0x98badcfe,
	                0x10325476]
		else:
			self._h = registers
		#Save the bytes of the message passed through so far.
		self._message_byte_length = message_byte_length

	def process_chunk(self,chunk):
		#Save current registers value.
		AA = self._h[0]
		BB = self._h[1]
		CC = self._h[2]
		DD = self._h[3]
		#Round one.
		self._h = general_round(h = self._h,X = chunk,func = F,s_vals = (3,7,11,19),
			k_update_rule = lambda x: x)
		#Round two.
		self._h = general_round(h = self._h,X = chunk,func = G,s_vals = (3,5,9,13),
			k_update_rule = lambda x: (x / 4 + (x % 4) * 4),constant = 0x5a827999)
		#Round three.
		k_vals = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)
		self._h = general_round(self._h,chunk,func = H,s_vals = (3,9,11,15),
			k_update_rule = lambda x: k_vals[x],constant = 0x6ED9EBA1)
		#Update internal vector.
		self._h[0]  = (self._h[0] + AA) % 2 ** 32
		self._h[1]  = (self._h[1] + BB) % 2 ** 32
		self._h[2]  = (self._h[2] + CC) % 2 ** 32
		self._h[3]  = (self._h[3] + DD) % 2 ** 32	

	def md4(self,data):
		'''
		The algorithm written is based on the RFC: https://tools.ietf.org/html/rfc1320
		This is the compression function that is ran on each 512 bit chunk of message data.
		'''
		#Fit to num bytes read so far.
		data_left = data[self._message_byte_length:]
		#Get the number of full blocks.
		num_blocks = len(data_left) / 64
		remainder = len(data_left) % 64
		#Loop over all the blocks.
		if (num_blocks != 0):
			for i in range(num_blocks):
				#Convert data to unsigned integers format.
				#For more about the struct module: https://docs.python.org/3/library/struct.html#struct.pack)
				curr_block = struct.unpack("@16I",
								data_left[i * 64: (i + 1) * 64])
				
				self.process_chunk(curr_block)
				self._message_byte_length += 64
			#Now apply sha1 padding.data
		padding = sha1_padding(data)
		#Compute for last block.
		last_block = data_left[-remainder:] + padding
		#Last block size will be 64 or 128 bytes.
		if (len(last_block) != 64):
			self.process_chunk(struct.unpack("@16I",last_block[:64]))
			last_block = last_block[64:]
		self.process_chunk(struct.unpack("@16I",last_block))
		return struct.pack("@4I", *self._h)

if __name__=="__main__":
	"Testing code taken from https://gist.github.com/bonsaiviking/5644414"
	test = (
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536")
        )
	for t, h in test:
		result = MD4().md4(t)
		if result == h.decode("hex"):
			print "pass"
		else:
			print "FAIL: {0}: {1}\n\texpected: {2}".format(t, result, h)