
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
    def __init__(self ,seed ,internal_state = None):
        '''
        Constructor of the MT19937 class.
        Inputs:
            - seed: The seed we will use for the generator.
            - internal_state: In the case we will create a "spliced" generator.
        '''
        # Initialize the index to 0.
        self.index = 0
        # Initialize the state vector.
        if internal_state == None:
            self.mt = [0] * 624
            # Initial state will be the input seed.
            self.mt[0] = seed
            for i in range(1 ,624):
                self.mt[i] = _int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)
        else:
            self.mt = internal_state
            self.index = len(internal_state)

    # This is also called the temper function.
    def extract_number(self):
        # Check if index passed the state vector's length.
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

        # Increment the index.
        self.index = self.index + 1

        return _int32(y)

    def twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the least significant bits of the next number.
            y = _int32((self.mt[i] & 0x80000000) + \
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

            # Initialize index back to 0.
            self.index = 0



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
    # Note:At first I will write the function as simple as possible to ignore bugs as much as I can
    # later I will fix the code in order to save some lines and computations.
    # Computations are a bit complicated.
    # Extract all 3 parts.
    first_part = ((2 ** 14 - 1) << 18) & num
    second_part = ((2 ** 4 - 1) << 14) & num
    third_part = (2 ** 14 - 1) & num
    a1 = first_part
    lsb_a2 = (a1 >> 18) ^ third_part
    y = (a1 | second_part) | lsb_a2
    # return _int32(y)

    # print "After first phase:%d" % y


    # Now invert: y ^= (y << 15) & 4022730752'
    first_part = ((2 ** 15 - 1) << 17) & y
    second_part = ((2 ** 2 - 1) << 15) & y
    third_part = (2 ** 15 - 1) & y

    # Compute part of b2.
    part_b2 = (third_part << 15) & 4022730752
    # Get two last bits of part_b2.
    lsb_b2 = ((2 ** 2 - 1) << 15) & part_b2
    msb_a2 = second_part ^ lsb_b2
    a2 = msb_a2 | third_part
    # Get full b2.
    b2 = (a2 << 15) & 4022730752
    a1 = first_part ^ (b2 & ((2 ** 15 - 1) << 17))
    y = a1 | a2
    # print "After second phase: %d" % y

    # Now invert y ^= (y << 7) & 2636928640
    # This one is going to be a bit more complex so I added a few lines of code
    # in hope that it will make it more readable.(The code is based on hand written computations)
    first_part = ((2 ** 7 -1) << 25) & y
    second_part = ((2 ** 18 - 1) << 7) & y
    third_part = (2 ** 7 - 1) & y

    # Get last 7 bits of b2.
    lsb_7_b2 = (third_part << 7) & 2636928640
    # Get another 7 bits of a2 to get total last 14 bits of a2.
    lsb_14_a2 = (second_part ^ lsb_7_b2) | third_part

    # Now get last 14 bits of b2.
    lsb_14_b2 = (lsb_14_a2 << 7) & 2636928640
    lsb_21_a2 = (second_part ^ lsb_14_b2) | third_part
    # Get last 21 bits of b2.
    lsb_21_b2 = (lsb_21_a2 << 7) & 2636928640

    # Get a2 completely.
    a2 = (second_part ^ (((2 ** 18 - 1) << 7) & lsb_21_b2)) | third_part
    b2 = (a2 << 7) & 2636928640
    a1 = first_part ^ (((2 ** 7 - 1) << 25) & b2)
    y = a1 | a2
    # print "After third step:%d" % y

    # Last part will be to invert y ^= (y >> 1)
    msb_a1 = (2 ** 31) & y
    second_part = ((2 ** 30 - 1) << 1) & y
    third_part = 1 & y

    a1 = msb_a1
    # Figure iteratively a1.Go through each bit of the result of second_part
    for i in range(30):
        a1 |= (second_part ^ ((a1 & (2 ** (31 - i))) >> 1)) & (2 ** (30 - i))

    # Extract a2.
    a2 = third_part ^ ((a1 & 2) >> 1)
    y = a1 | a2
    return y