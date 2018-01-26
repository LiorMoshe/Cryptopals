# coding: utf-8
'''Implementation of the cryptopals crypto challenges.
The program will get TWO command line arguments.
The first argument will represent the number of set of the crypto challenges
we will run and the second number will represent the number of challenge in this set
that will be run.
In this program I assume both cmd arguments are strings of integers.
Lior Moshe 2017'''
from funcs import *

if __name__ == "__main__":
    # Extract command line argument to know which challenge code to test.
    if (len(sys.argv) != 3):
        print("The program receives exactly 2 command line arguments:number of set and number of challenge.")
        exit()
    num_set = int(sys.argv[1])
    num_challenge = int(sys.argv[2])

    # Test challenge1.
    if (num_set == 1 and num_challenge == 1):
        if (hex_to_base64(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
                == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n"):
            print("SUCCESS")
        else:
            print("FAILURE:")

    # Test challenge2.
    if (num_set == 1 and num_challenge == 2):
        if (xor_strings("1c0111001f010100061a024b53535009181c".decode("hex"),
                        "686974207468652062756c6c277320657965".decode("hex"))
                == "746865206b696420646f6e277420706c6179".decode("hex")):
            print("SUCCESS")
        else:
            print("FAILURE:")

    # Test Challenge3.
    if (num_set == 1 and num_challenge == 3):
        plaintext, key, score = decrypt_single_byte_xor(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode("hex"))
        print("Decryption result:", plaintext)

    # Test challenge4.
    if (num_set == 1 and num_challenge == 4):
        '''
		In challenge 4 we got a file full of strings of the same length that ONLY ONE
		of them was encrypted by a single character using the XOR operation. We will use
		the code written for challenge3 in order to find this character.
		Note:All the strings in the file are encoded in hex.
		'''
        # Read all lines from the file.Use read mode.
        my_file = open("set1challenge4.txt", "r")
        my_strings = my_file.readlines()
        # Remove all \n from strings.
        my_strings = [curr_str.replace("\n", "") for curr_str in my_strings]
        # Iterate until we find the max score,the cipher text and the index of the string that was encrypted.
        key = None
        best_score = 0.0
        plaintext = None
        encrypted_str = None
        # Go over all strings until we get to the one with the max score.
        for curr_str in my_strings:
            curr_plaintext, curr_key, curr_score = decrypt_single_byte_xor(curr_str.decode("hex"))
            if (curr_score > best_score):
                key = curr_key
                best_score = curr_score
                plaintext = curr_plaintext
                encrypted_str = curr_str
        print("The final key:", key)
        print("Encrypted string:", encrypted_str)
        print("The plaintext:", plaintext)

    # Test challenge5.
    if (num_set == 1 and num_challenge == 5):
        '''
		In challenge5 all we have to do is implement the repeating xor key scheme and play
		with it a little bit.
		'''
        encrypted = repeating_xor_key("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
                                      "ICE")
        print(encrypted.encode("hex"))
        decrypted = repeating_xor_key(encrypted, "ICE")
        print(decrypted)

    # Test challenge6.
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
        # Read the file contents.
        my_file = open("set1challenge6.txt", "r")
        ciphertext = my_file.read()
        # Base64 decode.
        ciphertext = base64.b64decode(ciphertext)
        # Test hamming distance function.
        if (hamming_distance("this is a test", "wokka wokka!!!") == 37):
            print("SUCCESS hamming distance")
        # Get top3 key sizes.
        f_keysize, s_keysize, t_keysize = find_keysize(ciphertext, 2, 40)
        print("Top 3:%d %d %d" % (f_keysize, s_keysize, t_keysize))
        # Get key for each keysize.
        f_key = break_repeating_xor(ciphertext, f_keysize)
        s_key = break_repeating_xor(ciphertext, s_keysize)
        t_key = break_repeating_xor(ciphertext, t_keysize)
        print("Key for best key size results:", f_key)
        print("Produced plaintext:", repeating_xor_key(ciphertext, f_key))
        print("Key for second best key size results:", s_key)
        print("Produced plaintext:", repeating_xor_key(ciphertext, s_key))
        print("Key for third best key size results:", t_key)
        print("Produced plaintext:", repeating_xor_key(ciphertext, t_key))

    # Test challenge7.
    if (num_set == 1 and num_challenge == 7):
        '''
		Read from a file a base64'd content that was encrypted in AES-128 in ECB mode
		we will use the pycrypto library to decrypt it.(Writing AES by ourselves can be rough).
		The given key is YELLOW SUBMARINE
		'''
        my_file = open("set1challenge7.txt", "r")
        content = base64.b64decode(my_file.read())
        print("Decrypted:", AES_ECB_decrypt(content, "YELLOW SUBMARINE"))

    # Test challenge8.
    if (num_set == 1 and num_challenge == 8):
        '''
		In this challenge we will detect the use AES in ECB mode.
		We will do this by using the fact the ECB is STATELESS.
		'''
        my_file = open("set1challenge8.txt", "r")
        # Read from the file.
        my_strings = my_file.readlines()
        my_strings = [curr_str.replace("\n", "") for curr_str in my_strings]
        for curr_str in my_strings:
            if (detect_AES(curr_str.decode("hex"))):
                print("Detected AES for ciphertext:", curr_str)

    # Test challenge9
    if (num_set == 2 and num_challenge == 1):
        if (PKCS7("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"):
            print("SUCCESS")

    # Test challenge10.
    if (num_set == 2 and num_challenge == 2):
        '''
		In this challenge we will implement AES in CBC(cipher block chain) mode
		of operation by using the AES-ECB code that we wrote earlier.
		We will test our code by decrypting the ciphertext in the file set2challenge2.txt
		'''
        my_file = open("set2challenge2.txt", "r")
        content = base64.b64decode(my_file.read())
        # We are given the iv:
        iv = chr(0) * 16
        print(AES_CBC_dec(content, "YELLOW SUBMARINE", iv))

    # Test challenge11.
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
            if (detect_AES_mode(ciphertext, 16) == AES.MODE_ECB):
                print("I'm sensing there was use of ECB.")
            else:
                print("I'm sensing CBC is around here.")

    # Test challenge12.
    if (num_set == 2 and num_challenge == 4):
        '''
		In this challenge we will implement byte at a time decryption of ECB mode,
		we will use a function(defined above) that encrypts with the same key each time(but
			the key is unknown) and each time the functions adds an unknown string to the plaintext
			before the encryption,we will show that by feeding this function different plaintexts
			we can find the unknown strings.
		'''
        # First we will find out the number of blocks in the cipher(it's size).
        str_len, starting_num_blocks = find_target_length()
        # Now decrypt one byte at a time.
        print"After decryption:%s " % dec_ecb(str_len, starting_num_blocks)

    # Test challenge13.
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
        # Some random user input.
        inp_profile = profile_for("liortheking@gmail.com")
        # Generate profile and encrypt it.
        ciphertext = ECB_enc_randkey(inp_profile)
        # Find index of the string user in the inp_string.
        user_index = inp_profile.find("user") % BLOCKSIZE
        required_offset = BLOCKSIZE - user_index
        # We want user to hold it's own block.
        inp_profile = 'A' * required_offset + inp_profile
        ciphertext = ECB_enc_randkey(inp_profile)
        # Num blocks.
        num_blocks = len(ciphertext) / BLOCKSIZE
        # Get block with decryption of admin with correct padding.
        target_block = "admin" + chr(11) * 11
        # Create attacker profile.
        attacker_profile = profile_for('A' * 10 + target_block + "@gmail.com")
        attacker_cipher = ECB_enc_randkey(attacker_profile)
        # Extract target block.
        target_block = extract_keysize_block(attacker_cipher, 2, BLOCKSIZE)
        ciphertext = ciphertext[:(num_blocks - 1) * BLOCKSIZE] + target_block
        # Print result.role = admin successfuly.
        print AES_ECB_decrypt(ciphertext, unknown_key)

    # Test challenge14
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
        # Found out the random string's length.
        prev_block = extract_keysize_block(ecb_enc_prepend_rand("", unknown_key), 1, BLOCKSIZE)
        for i in range(BLOCKSIZE):
            curr_block = extract_keysize_block(ecb_enc_prepend_rand("A" * (i + 1), unknown_key), 1, BLOCKSIZE)
            if (curr_block == prev_block):
                # Save offset that we need to add.
                offset = i
                break
            prev_block = curr_block
        # Prepended string will be of length BLOCKSIZE
        prepended_str = random_bytes + offset * 'A'
        # Count number of blocks of target.
        str_len, num_blocks = find_target_length(prepended_str)

        print "Decrypted: %s" % dec_ecb(str_len, num_blocks - 1, check_block=2, prepend=prepended_str)

    # Test challenge15.
    if (num_set == 2 and num_challenge == 7):
        '''
		The purpose of this challenge was to simply write the PKCS7_validation function(for later use
			in padding oracle attack).
		'''
        print PKCS7_validation(PKCS7("Ice cube ", BLOCKSIZE))

    prepend_str = "comment1=cooking%20MCs;userdata="
    append_str = ";comment2=%20like%20a%20pound%20of%20bacon"

    # Test challenge16.
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
        cipher = cbc_enc_prepend_append("admin=true", unknown_key, iv)
        print (admin_verifier(cipher, unknown_key, iv))
        target_block = ";admin=true;" + chr(4) * 4
        cbc_bitflip_attack(unknown_key, iv, target_block)

    # Test challenge17.
    if (num_set == 3 and num_challenge == 1):
        '''
		Padding oracle attack.
		For deep explanation of how this works see: https://robertheaton.com/2013/07/29/padding-oracle-attack/
		'''
        # Produce a plaintext of some string.
        ciphertext, iv = enc_string(unknown_key)
        print "Result of padding oracle attack: %s" % oracle_attack(ciphertext, unknown_key, iv)

    # Test challenge18.
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
        # This is the ciphertext that we are given in the challenge.
        plaintext = "liortheking" * 10
        ciphertext = AES_CTR(plaintext, "YELLOW SUBMARINE", struct.pack("<Q", 8))
        print("The ciphertext:", ciphertext)
        print("After decryption:", AES_CTR(ciphertext, "YELLOW SUBMARINE", struct.pack("<Q", 8)))

    # Test challenge19.
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
        my_file = file("set3challenge3.txt", "r")
        # Read plaintexts.
        plaintexts = [curr_str.replace("\n", "") for curr_str in my_file.readlines()]
        ciphertexts = []
        fixed_nonce = struct.pack("<Q", 8)
        # Compute all the ciphertexts.
        for i in range(len(plaintexts)):
            ciphertexts.append(AES_CTR(base64.b64decode(plaintexts[i]), unknown_key, fixed_nonce))

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
        # Find second byte.
        digraphs = [digraph.title() for digraph in common_digraphs.keys()]
        # Add some digraphs.
        digraphs += ['Of', 'So', 'Or', 'To', 'He', 'In', 'Wa', 'A ', 'I ', 'Po', 'Be', 'Ar']
        trigraphs = [trigraph.title() for trigraph in common_trigraphs.keys()]
        trigraphs += ['And', 'Thi', 'Com', 'But', 'All', 'She', 'Yet', 'Wha', 'Whe']
        four_letter_combos = ["What", "This", "When", "Unti", "From", 'Comi', 'Bein', ]
        five_letter_combos = ["Until", "Being", "Around", "Comin", "I hav"]
        six_letter_combos = ["I have", "Coming"]
        seven_letter_combos = ["Eightee", "A terri"]
        eight_letter_combos = ["Eighteen", "He might", "Transfor", "He might"]
        nine_letter_combos = ["A terribl", "Eighteent", "Transform"]
        ten_letter_combos = ["A terrible", "Eighteenth", "Transforme", "What voice", "Until her "]
        eleven_letters = ["Coming with", "Eighteenth-", "I have pass"]
        twelve_letters = ["Yet I number"]
        thirteen_letters = ["In the casual", "He might have"]
        fourteen_letters = ["Until her voic"]
        fifteen_letters = ["Until her voice", "I have met them"]
        sixteen_letters = ["A terrible beaut"]
        seventeen_letters = ["Coming with vivid", "A terrible beauty"]
        eighteen_letters = ["Eighteenth-century"]
        nineteen_letters = ["So daring and sweet"]
        twenty_letters = ["Or polite meaningles"]
        twentyone_letters = ["Or polite meaningless", "He, too, has resigned"]
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
        combos = [digraphs, trigraphs, four_letter_combos, five_letter_combos, six_letter_combos, seven_letter_combos \
            , eight_letter_combos, nine_letter_combos, ten_letter_combos, eleven_letters, twelve_letters \
            , thirteen_letters, fourteen_letters, fifteen_letters, sixteen_letters, seventeen_letters \
            , eighteen_letters, nineteen_letters, twenty_letters, twentyone_letters, twentytwo_letters \
            , twentythree_letters, twentyfour_letters, twentyfive_letters, twentysix_letters, \
                  twentyseven_letters, twentyeight_letters, twentynine, thirty, thirtyone, thirtytwo \
            , thirtythree, thirtyfour, thirtyfive, thirtysix, thirtyseven, thirtyeight]

        for i in range(1, len(combos) + 1):
            keystream += chr(find_byte(ciphertexts, keystream, combos[i - 1]))
        # Review results.
        print "Printing substitution attack results"
        for i in range(len(ciphertexts)):
            result = xor_strings(ciphertexts[i], keystream)
            print "Ciphertext length:%d result length:%d" % (len(ciphertexts[i]), len(result))
            print "Result:%d String: %s" % (i, result)
        # Print the plaintexts for comparison.
        print "Printing plaintexts"
        for i in range(len(plaintexts)):
            print "Num: %d Plaintext:%s" % (i, base64.b64decode(plaintexts[i]))

    # Test challenge20.
    if (num_set == 3 and num_challenge == 4):
        '''
		Break fixed-nonce CTR with statistics.
		'''
        my_file = file("set3challenge4.txt", "r")
        plaintexts = [curr_str.replace("\n", "") for curr_str in my_file.readlines()]
        ciphertexts = []
        smallest_length = sys.maxint
        for i in range(len(plaintexts)):
            curr_cipher = AES_CTR(base64.b64decode(plaintexts[i]), unknown_key, struct.pack("<Q", 8))
            ciphertexts.append(curr_cipher)
            if (len(curr_cipher) < smallest_length):
                smallest_length = len(curr_cipher)

        # Now use the smallest length to truncate all ciphertexts.
        # Strings are immutable in python so we will have to create a new string.
        final_str = ""
        for i in range(len(ciphertexts)):
            final_str += ciphertexts[i][:smallest_length]

        # Now break as repeating key xor.Same as challenge 6.
        key = break_repeating_xor(final_str, smallest_length)
        print("Produced ciphertexts:", repeating_xor_key(final_str, key))
    # After this is solved there is not much more work left to do.


    # Test challenge21.
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

    # Test challenge22.
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
        seed = int(time.time()) + random.randint(40, 1000)
        print "Chose seed: %d" % seed
        rng = MT19937(seed)
        extracted_num = rng.extract_number()
        curr_time = seed + random.randint(40, 1000)
        # Find the seed.
        for i in range(curr_time - 1001, curr_time):
            if MT19937(i).extract_number() == extracted_num:
                print "Found the seed: %d" % i

    # Test challenge23.
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
        # Create a new MT199937 extract 624 outputs and use the untemper function to clone it.
        print "We will print out comparisons between the original PRNG and the clonged PRNG"
        rng = MT19937(50)
        outputs = []
        for i in range(624):
            outputs.append(rng.extract_number())

        # Use untemper function.
        initial_state = []
        for i in range(623, -1, -1):
            initial_state = [untemper(outputs[i])] + initial_state

        # Create "spliced" MT19937,when it is spliced the seed doesn't matter
        cloned = MT19937(0, internal_state=initial_state)
        # Now check if we get the exact same numbers.
        for i in range(100):
            print "Original RNG extracted: %d" % rng.extract_number()
            print "Clone extracted: 	   %d" % cloned.extract_number()

    # Test challenge24.
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
        # Test the stream cipher.
        plaintext = os.urandom(random.randint(1, 100)) + 'A' * 14
        seed = ord(os.urandom(1))
        print "Secret seed chosen: %d" % seed
        ciphertext = mt19937_stream_cipher(plaintext, seed)
        # Count number of 4 byte blocks.
        num_full_blocks = len(ciphertext) / 4
        # Find last block of the keystream.
        keystream = xor_strings(extract_keysize_block(ciphertext, num_full_blocks, 4),
                                'A' * 4)
        # Convert the keystream string back to a number.
        keystream = struct.unpack("<L", keystream)[0]
        print keystream
        # Go over each possible seed and stop when we get to the seed that produces the same keystream.
        for i in range(2 ** 16):
            # Create a new MT19937 PRNG with the current seed.
            curr_prng = MT19937(i)
            for j in range(num_full_blocks):
                num = curr_prng.extract_number()
            # Compare to the number that we got.
            if (num == keystream):
                print "Found it %d" % i
                break

        '''
		We will use the same idea to generate a "password reset token" using MT19937 seeded from the current time
		and we will write a function that given some password token checks if it was created with a MT19937 PRNG
		seeded with the current time.
		'''
        # Test
        print "Seed a MT19937 PRNG with the current time"
        print "Function says: " + str(test_password_token(MT19937(int(time.time())).extract_number()))
        print "Now testing for some random seed"
        print "Function says: " + str(test_password_token(MT19937(ord(os.urandom(1))).extract_number()))

    # Test challenge25.
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
        print "Print out the found plaintext after each byte found using a brute-force solution."
        my_file = file("set4challenge1.txt", "r")
        # Read all the plaintexts.
        plaintext = AES_ECB_decrypt(base64.b64decode(my_file.read()), "YELLOW SUBMARINE")
        # We will use the random key saved in unknown_key variable.
        ciphertext = AES_CTR(plaintext, unknown_key, nonce)
        found_plaintext = ""
        # Now the attacker will discover one byte at a time using the edit function.
        for i in range(len(plaintext)):
            # Check all byte values.
            for guess in range(256):
                edited_ciphertext = edit_cipher(ciphertext, unknown_key, i, chr(guess))
                if (edited_ciphertext == ciphertext):
                    # Means we found one byte of the plaintext.
                    found_plaintext += chr(guess)
                    break
            print "Found so far %s" % found_plaintext
        print "Found plaintext: %s" % found_plaintext

    # Test challenge26.
    if (num_set == 4 and num_challenge == 2):
        '''
		CTR bitflipping.
		We will reimplement the attack we performed on CBC mode in challenge16 to show that
		CTR is vulnerable to bitflipping attacks as well.
		We can even say that it is easier to perform a bitflip attack in CTR mode than in CBC mode,
		in the previous challenge we showed that we can easily seek forward into the ciphertext in CTR
		mode by using the edit_cipher function that we wrote,we can use this function to perform a much simpler
		bitflipping attack than the one that was performed when we used CBC mode.
		'''
        # 16 byte target block.
        print "Running the bitflip attack on AES in CTR mode."
        target_block = ";admin=true;" + 'A' * 4
        print "The payload block will be: %s" % target_block
        ctr_bitflip_attack(unknown_key, nonce, target_block)

    # Test challenge27.
    if (num_set == 4 and num_challenge == 3):
        '''
		Recover key from CBC with key=IV.
		In this challenge we will show why using the same value for the key and iv under CBC mode can
		be insecure.
		We will take some 3 block sized message : P1-P2-P3 and encrypt it by using the same value for the key
		and the iv receiving: C1-C2-C3.
		Now as the attacker we will modify the ciphertext to fit the following format: C1-0-C1(0 means BLOCKSIZE of null bytes).
		By decrypting this ciphertext we can completely find the value of the key which is simply the iv.
		Why?
		Because we can discover the intermediate mode of C1.Let's call the plaintext blocks received from the edited
		ciphertext P1'-P2'-P3',we can see that:
		P3' = decrypt(C1) XOR 0 = decrypt(C1)
		P1' = decrypt(C1) XOR IV  ==> therefore: IV = P1' XOR decrypt(C1) = P1' XOR P3'
		So we will simply compute the value of the IV(very easily)
		'''
        print "We will show why using the same value for the key and iv can be insecure."
        print "Your secret key: %s" % unknown_key
        plaintext = "key=iv insecure " * 3
        ciphertext = AES_CBC_enc(plaintext, unknown_key, unknown_key, check_encoding=True)
        # Modify the ciphertext.
        C1 = extract_keysize_block(ciphertext, 1, BLOCKSIZE)
        modified_cipher = C1 + chr(0) * BLOCKSIZE + C1
        modified_plaintext = AES_CBC_dec(modified_cipher, unknown_key, unknown_key)
        # Compute the key.
        key = xor_strings(extract_keysize_block(modified_plaintext, 1, BLOCKSIZE),
                          extract_keysize_block(modified_plaintext, 3, BLOCKSIZE))
        # Check if we got it right.
        if (key == unknown_key):
            print "Guess what the attacker found: %s" % key
            print "Moohaha I found the key,I am going to rule this planet."

    # Challenge28
    if (num_set == 4 and num_challenge == 4):
        print "There is nothing to test in challenge28,it's just an implementation."

    # Challenge29.
    if (num_set == 4 and num_challenge == 5):
        '''
		Break a SHA-1 keyed MAC using length extension.
		Turns out secret prefix SHA-1 MACs are breakable.
		The main idea that this attack is based on is that we can take the output from
		the SHA-1 algorithm and pass it through the algorithm again,therefore we feed more data
		by taking some output hash value.
		The attack will be that we will be able to generate a valid MAC without knowing
		the secret key that the user is using to generate a message that gives us
		certain previleges(like admin=true).We will do it by first guessing the length of
		the key that was used(because each key length derives different sha-1 padding).
		From the attacker standpoint,we can see the MAC of the original message sent from
		some user but we don't know the secret prefix key(we don't even know it's length).
		Steps of the attack:
		1. Get the SHA-1 digest of the true message and split it to 5 words.
		2. For each guess of the length of the key prepend key padding to the original
		message and apply sha-1 padding,i.e. for the message labled "original message"
		we will get 'A' * keylength + original message + sha-1 padding.
		3. Pass in the internal state words calculated in step 1 to a new sha-1 and add the
		extension data we wish to pass(in our case ;admin=true;)
		Note:The secret key will be a randomly chosen words from the usr/share/dict/words file.
		We will check all word lengths up to 20 bytes.(This is an assumption to save
			some time,in a real attack we will have to check a larger interval).
		'''
        print "Executing the attack on SHA-1 keyed mac using length extension"
        original_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        # Read secret key from usr/share/dict/words.
        words = open("words", "r").readlines()
        secret_key = words[random.randint(0, len(words) - 1)].replace("\n", '')
        # Get MAC of original message.
        original_mac = sha1_secret_mac(original_message, secret_key)
        # Now as the attacker seperate the mac to 5 words.
        sha1_registers = (int(original_mac[0:8], 16),
                          int(original_mac[8:16], 16),
                          int(original_mac[16:24], 16),
                          int(original_mac[24:32], 16),
                          int(original_mac[32:], 16))
        extension_message = ";admin=true"
        # Run over all key lengths.
        for keylen in range(20):
            # keylen bytes precedes the original message.
            curr_message = 'A' * keylen + original_message
            # Compute the required padding for current value of keylen.
            padding = sha1_padding(curr_message, mode=">")
            total = curr_message + padding
            # Create our forged message,take the message and the required padding and add the extension.
            forged_message = curr_message + padding + extension_message
            # Get mac of new forged message.Use saved sha1_registers and
            # skip the right amont of bytes(length of the string saved in total).
            forged_mac = sha1(forged_message, sha1_registers, len(total))
            total_message = original_message + padding + extension_message
            # Check if the forged_mac is verified,if so we got admin privileges.
            if (verify_mac(sha1, total_message, forged_mac, secret_key)):
                print "Got my message authenticated:%s" % (total_message)

    # Challenge30.
    if (num_set == 4 and num_challenge == 6):
        '''
		Implement the same attack on MD4 algorithm.
		More about MD4: https://tools.ietf.org/html/rfc1320
		This time I implemented the full md4 algorithm in md4.py
		1.Get the digest of the original message and save the 4 MD4 registers that
		are given in this mac.
		2.Iterate over all possible key lengths and do:
			2.1. For the current key length find the needed MD4 padding using
				 the sha1_padding function(sha1 and md4 use the same padding scheme)
		    2.2. Add the extension_message which is our payload.
		    2.3. Compute the MAC of the forged message by initializing the registers
		    	 for the MD4 registers to the values computed in step 1.
		    2.4. Compute the MAC of the total message(with the secret prefix key
		    	 that the attacker doesn't know it's value) and compare to the value
				 of the MAC of the forged message,if it's the same value we found the
				 key length and we can successfuly send messages while being authenticated
				 as someone else.
		'''
        print "Executing the attack on MD4 keyed MAC using length extension"
        original_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        # Read secret key from usr/share/dict/words.
        words = open("words", "r").readlines()
        secret_key = words[random.randint(0, len(words) - 1)].replace("\n", '')
        # Get MAC of original message.
        original_mac = MD4().md4(secret_key + original_message)
        # Unpack the string of the mac to 4 unsigned integers.
        md4_registers = struct.unpack("@4I", original_mac.decode("hex"))
        # md4_registers = [md4_registers[i] for i in range(len(md4_registers))]

        extension_message = ";admin=true"
        # Define the function that receives a message and returns it's md4 hash value.
        func = lambda x: MD4().md4(x)
        # Loop over all possible key lengths.
        for keylen in range(20):
            # keylen bytes precedes the original message.
            curr_message = 'A' * keylen + original_message
            # Compute the required padding for current value of keylen.
            padding = sha1_padding(curr_message)
            total = curr_message + padding
            # Create our forged message,take the message and the required padding and add the extension.
            forged_message = curr_message + padding + extension_message
            # Get mac of new forged message.Use saved sha1_registers and
            # skip the right amont of bytes(length of the string saved in total).
            forged_mac = MD4(registers=md4_registers,
                             message_byte_length=len(total)).md4(forged_message)
            total_message = original_message + padding + extension_message
            # Check if the forged_mac is verified,if so we got admin privileges.
            if (verify_mac(func, total_message, forged_mac, secret_key)):
                print "Got my message authenticated:%s" % (total_message)

    # Challenge31.
    if (num_set == 4 and num_challenge == 7):
        '''
		Implement and break HMAC-SHA1 with an artificial timing leak.
		About HMAC: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
		In short: The HMAC's algorithm is built so that it wouldn't be possible
		to use length extension attacks like the ones we did in previous challenges.
		RFC: https://tools.ietf.org/html/rfc2104
		In this challenge the server that is implemented in artificialLeakServer.py will create a web
		server that allows the user to enter via the URL two inputs:
		    -The name of the file that we will calculate it's hash.
		    -The hash value that we think this file has.
		We will show that if there are timing leaks in the server(i.e. the insecure_compare
		function in artificialLeakServer.py) we can find out the hash of any file.
	    Assuming that we know there is a HMAC-SHA1 ran in the server(this means the output
	    is of size 20 bytes).
        The code for the server that has the artificial timing leak is in artificalLeakServer.py
        and it is implemented using web.py framework.
        The code of the attacker that uses the timing leak in the server in order to find
        out the secret signature is in artificialLeakClient.py.
		'''
        from artificialLeakClient import discover_char

        print "Challenge31:Implement and break HMAC-SHA1 using an artificial timing leak."

        sig = ""

        #We know that the hmac-sha1 signature is 40 bytes long.
        for i in range(40):
            sig += discover_char(sig)
            print "Current: " + sig

        print "The final signature that we found is: " + sig

    #Challenge32.
    if (num_set == 4 and num_challenge == 8):
        print "This challenge's implementation is the same as the implementation" \
              " of challenge 31.\n If there is very small artificial timing leak what we will" \
              " do is convert it to a big artificial timing leak by sending several requests to the " \
              " server so the timing leaks add up to become a noticable timing leak,so even if there is" \
              " a very small timing leak in the server an attacker can use it to find out the signature" \
              " of any file on the user's computer."

