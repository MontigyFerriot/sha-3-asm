/**
  * Implementation based on reference implementaion
  * by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
  * Michaël Peeters, Gilles Van Assche and Ronny Van Keer,
  * For more information, feedback or questions, please refer to our website:
  * https://keccak.team/
  */

#include "sha3.hpp"

#include <sstream>
#include <cstring>
#include <algorithm>

static uint64_t rol64(uint64_t a, unsigned offset)
{
	return (a << offset) ^ (a >> (64 - offset));
}

int sha3::len_to_int(sha3::len l)
{
	return static_cast<int>(l);
}

std::string sha3::hash::str() const
{
	std::stringstream sstr;

	for (int i = 0; i < sha3::len_to_int(len); ++i)
		sstr << std::hex << static_cast<int>(digest[i]);

	return sstr.str();
}

std::ostream& operator<<(std::ostream& ost, const sha3::hash& h)
{
	for (int i = 0; i < sha3::len_to_int(h.len); ++i)
		ost << std::hex << static_cast<int>(h.digest[i]);

	ost << std::dec;

	return ost;
}
/**
  * Function to compute the Keccak[r, c] sponge function over a given input.
  * @param  rate            The value of the rate r.
  * @param  capacity        The value of the capacity c.
  * @param  input           Pointer to the input message.
  * @param  input_len     The number of input bytes provided in the input message.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         These <i>n</i> bits must be in the least significant bit positions
  *                         and must be delimited with a bit 1 at position <i>n</i>
  *                         (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                         from position <i>n</i>+1 to position 7.
  *                         Some examples:
  *                             - If no bits are to be appended, then @a delimitedSuffix must be 0x01.
  *                             - If the 2-bit sequence 0,1 is to be appended (as for SHA3-*), @a delimitedSuffix must be 0x06.
  *                             - If the 4-bit sequence 1,1,1,1 is to be appended (as for SHAKE*), @a delimitedSuffix must be 0x1F.
  *                             - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedSuffix must be 0x8B.
  * @param  output          Pointer to the buffer where to store the output.
  * @param  output_len   The number of output bytes desired.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  */
/** A readable and compact implementation of the Keccak sponge functions
  * that use the Keccak-f[1600] permutation.
  */
void Keccak(unsigned int rate, const unsigned char *input,
		std::size_t input_len , unsigned char suffix,
		unsigned char *output, std::size_t output_len, keccakf_func keccakf)
{
    	uint8_t state[200];
	uint64_t *state64 = (uint64_t*)state;
    	unsigned int block_size = 0;
    	unsigned int i;

	// convert to bytes
	rate = rate / 8;

    	// initialize the state
    	memset(state, 0, sizeof(state));

    	// absorb all the input blocks
    	while (input_len > 0) {
		        block_size = std::min(input_len, static_cast<std::size_t>(rate));

    	    	for (i = 0; i < block_size; i++)
    	    	    	state[i] ^= input[i];

    	    	input     += block_size;
    	    	input_len -= block_size;

    	    	if (block_size == rate) {
    	    	    	keccakf(state64);
    	    	    	block_size = 0;
    	    	}
    	}

    	// Do the padding and switch to the squeezing phase
    	// Absorb the last few bits and add the first bit
	// of padding (which coincides with the delimiter in suffix)
    	state[block_size] ^= suffix;

    	// If the first bit of padding is at position rate-1, we need a whole new block
	// for the second bit of padding
    	if (((suffix & 0x80) != 0) && (block_size == rate - 1))
    	    	keccakf(state64);

    	// add the second bit of padding
    	state[rate - 1] ^= 0x80;

    	// switch to the squeezing phase
    	keccakf(state64);

    	// squeeze out all the output blocks
    	while (output_len > 0) {
		        block_size = std::min(output_len, static_cast<std::size_t>(rate));
    	    	memcpy(output, state, block_size);

    	    	output     += block_size;
    	    	output_len -= block_size;

    	    	if (output_len > 0)
    			keccakf(state64);
	}
}

// Function to compute SHAKE128 on the input message with any output length.
void shake128(const unsigned char *input, unsigned int input_len, unsigned char *output, int output_len, keccakf_func func)
{
	Keccak(1344, input, input_len, 0x1F, output, output_len, func);
}

// Function to compute SHAKE256 on the input message with any output length.
void shake256(const unsigned char *input, unsigned int input_len, unsigned char *output, int output_len, keccakf_func func)
{
    	Keccak(1088, input, input_len, 0x1F, output, output_len, func);
}

// Function to compute SHA3-224 on the input message. The output length is fixed to 28 bytes.
void sha3_224(const unsigned char *input, unsigned int input_len, unsigned char *output, keccakf_func func)
{
    	Keccak(1152, input, input_len, 0x06, output, 28, func);
}

// Function to compute SHA3-256 on the input message. The output length is fixed to 32 bytes.
void sha3_256(const unsigned char *input, unsigned int input_len, unsigned char *output, keccakf_func func)
{
    	Keccak(1088, input, input_len, 0x06, output, 32, func);
}

// Function to compute SHA3-384 on the input message. The output length is fixed to 48 bytes.
void sha3_384(const unsigned char *input, unsigned int input_len, unsigned char *output, keccakf_func func)
{
    	Keccak(832, input, input_len, 0x06, output, 48, func);
}

// Function to compute SHA3-512 on the input message. The output length is fixed to 64 bytes.
void sha3_512(const unsigned char *input, unsigned int input_len, unsigned char *output, keccakf_func func)
{
	Keccak(576, input, input_len, 0x06, output, 64, func);
}

sha3::hash sha3::make_hash(const std::string& msg, sha3::len len, keccakf_func func)
{
	sha3::hash hash(len);
	
	if (!func)
		return hash;

	const unsigned char *input = reinterpret_cast<const unsigned char*>(msg.data());
	std::size_t input_size = msg.size();
	unsigned char *output = static_cast<unsigned char *>(hash.digest.data());

	switch (len) {
	case sha3::len::sha3_empty:
		return hash;
	break;
	case sha3::len::sha3_224:
		sha3_224(input, input_size, output, func);
	break;
	case sha3::len::sha3_384:
		sha3_384(input, input_size, output, func);
	break;
	case sha3::len::sha3_256:
		sha3_256(input, input_size, output, func);
	break;
	case sha3::len::sha3_512:
		sha3_512(input, input_size, output, func);
	break;
	}

	return hash;
}

