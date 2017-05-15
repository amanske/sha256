from sys import stdin
import struct

# right-rotate function
def right_rot(x, n):
	return ((x >> n) | (x << (32-n))) & 0xFFFFFFFF

# Implementation based on https://en.wikipedia.org/wiki/SHA-2#Pseudocode 
# and http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
def sha256(message):

	# initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
	h_vals = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

	# initialize round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
	k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


	############################### PREPROCESSING #######################################
	

	# begin with the original message of length L bits

	length = len(message)
	# add a single 1-bit
	message += '80'.decode('hex_codec')

	# append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
	block = (length + 8 + 64) // 64 
	bit_length = block * 64
	padding = bit_length - length - 1 - 8
	for i in range(padding):
		message += '00'.decode('hex_codec')

	# add the bit length as a 64-bit big-endian
	message += ("%016X" % (length*8)).decode('hex_codec')
	

	####################################################################################

	
	# break message into 512-bit chunks.
	chunks = []
	for i in range(0, len(message), 64):
		chunks.append(message[i:i+64])

	# create a 64-entry message schedule array w[0..63] of 32-bit words
	for chunk in chunks:
		w = []
		# copy chunk into first 16 words w[0..15] of the message schedule array
		# and convert bin string to ints by blocks of 32 bits
		for i in range(0, len(chunk), 4):
			num = struct.unpack(">I", chunk[i:i+4])
			w.append(int(num[0]))
		
		# Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
		for i in range(16,64):
			s0 = right_rot(w[i-15], 7) ^ right_rot(w[i-15], 18) ^ (w[i-15] >> 3)
			s1 = right_rot(w[i-2], 17) ^ right_rot(w[i-2], 19) ^ (w[i-2] >> 10)
			w.append((s1 + w[i-7] + s0 + w[i-16]) & 0xFFFFFFFF)	

		# Initialize working variables to current hash value:
		a = h_vals[0]
		b = h_vals[1]
		c = h_vals[2]
		d = h_vals[3]
		e = h_vals[4]
		f = h_vals[5]
		g = h_vals[6]
		h = h_vals[7]

		####################### Compression function main loop ################################
		for i in range(64):
			s1 = right_rot(e, 6) ^ right_rot(e, 11) ^ right_rot(e, 25)
			ch = (e & f) ^ ((0xFFFFFFFF^e) & g)
			tmp1 = (h + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
			s0 = right_rot(a, 2) ^ right_rot(a, 13) ^ right_rot(a, 22)
			maj = (a & b) ^ (a & c) ^ (b & c)
			tmp2 = (s0 + maj) & 0xFFFFFFFF


			h = g
			g = f
			f = e
			e = (d + tmp1) & 0xFFFFFFFF
			d = c
			c = b
			b = a
			a = (tmp1 + tmp2) & 0xFFFFFFFF


		######################################################################################

		# add the compressed chunk to the current hash value
		h_vals[0] += a
		h_vals[1] += b
		h_vals[2] += c
		h_vals[3] += d
		h_vals[4] += e
		h_vals[5] += f
		h_vals[6] += g
		h_vals[7] += h
		# and with a 32 1-bit string to make sure that we have a 32-bit word
		for i in range(len(h_vals)):
			h_vals[i] = h_vals[i] & 0xFFFFFFFF

	# concatenate all h values and print them
	print "".join([struct.pack(">I", h) for h in h_vals]).encode('hex_codec')

for line in stdin:
	# decode the input since the exercise states 
	# "Note that it is the encoded bytes that must be hashed and not the ASCII characters in the hexadecimal encoding"
	sha256(line.strip().decode('hex_codec'))
