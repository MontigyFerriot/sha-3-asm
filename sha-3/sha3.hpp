#pragma once

#include <iostream>
#include <array>

typedef void (*keccakf_func) (uint64_t* state);

namespace sha3 {

enum class len {
	sha3_empty = 0,
	sha3_224 = 28,
	sha3_256 = 32,
	sha3_384 = 48,
	sha3_512 = 64,
};

int len_to_int(sha3::len l);
int len_to_int(sha3::len l);

struct hash
{
	hash()
	:digest(), len(sha3::len::sha3_empty) { }

	hash(sha3::len len)
	:digest(), len(len) { }

	unsigned bytes() const { return len_to_int(len); }
	unsigned bits()  const { return bytes() * 8; }
	std::string str() const;

	std::array<uint8_t, 64> digest;
	sha3::len len; // name sha_len instead
};


hash make_hash(const std::string& s, sha3::len len, keccakf_func=nullptr);

}; // namespace sha3

std::ostream& operator<<(std::ostream& ost, const sha3::hash& h);
