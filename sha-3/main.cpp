#include <iostream>
#include <fstream>
#include <string>
#include "sha3.hpp"
#include "windows.h"
#include <chrono>

#include <ios>

int getopt(int argc, char* const argv[], const char* optstring);
char* optarg = NULL;
int optind = 1;

const char* options = "ti:s:o:d:h";

static std::string help = "Sha3 hash generator\n"
"Usage: prog [OPTIONS] [-i FILE] WORDS...\n"
"Options: \n"
"\t-i - input file with words in line to be hashed\n"
"\t-s - hash size from {224, 256, 384, 512}. If not specified, hashes for all sizes are calculated.\n"
"\t-o - name of the output file. If not specified, output goes to stdout\n"
"\t-d - dll library containg asm keccak function\n"
"\t-h - prints help";

void all_hashes(const std::string& msg, std::ostream& ost, keccakf_func keccakf)
{
    std::array<sha3::len, 4> lengths = {sha3::len::sha3_224, sha3::len::sha3_256, sha3::len::sha3_384, sha3::len::sha3_512};

    for (sha3::len len : lengths) {
        sha3::hash hash = sha3::make_hash(msg, len, keccakf);

        ost << "SHA-" << hash.bits() << ": " << hash << "\n";
    }

    ost << std::endl;
}

using Clock = std::chrono::high_resolution_clock;

int main(int argc, char **argv)
{
    int c;
    bool is_input_file = false;
    bool is_hash_size = false;
    bool is_dll = false;
    bool is_output_file = false;

    std::string input_file = "undefined";
    std::string output_file = "undefined_output_file.txt";
    std::string dll_file;

    sha3::len sha3_len = sha3::len::sha3_224;

    if (argc == 1) {
        std::cout << help;
        return 0;
    }

    while (true) {
        c = getopt(argc, argv, options);

        if (c == -1)
            break;

        switch (c) {
        case 'i': // input file
            is_input_file = true;
            input_file = optarg;
        break;
        case 's': // hash size
            is_hash_size = true;
            sha3_len = static_cast<sha3::len>(std::stoi(optarg) / 8);
        break;
        case 'o': // output file
            is_output_file = true;
            output_file = optarg;
        break;
        case 'd': // dll library
            is_dll = true;
            dll_file = optarg;
        break;
        case 'h':
            std::cout << help;
            return 0;
        break;
        case '?':
            std::cout << "Unknown option: " << optarg << std::endl;
        break;
        }
    }

    if (!is_dll) {
        std::cout << "Dll not specified. Use -d option.\n";
    }

    HINSTANCE hinstance = LoadLibraryA(dll_file.c_str());
    if (!hinstance) {
        std::cout << "Cannot open dll: " << dll_file.c_str() << std::endl;
        return 0;
    }

    keccakf_func keccakf = (keccakf_func)GetProcAddress(hinstance, "keccakf");
    if (!keccakf) {
        std::cout << "Cannot load keccakf() func" << std::endl;
        return 0;
    }

    if (!is_input_file) {
        std::cout << "input file not specified" << std::endl;
        return 0;
    }
    std::ifstream ist;

    if (is_input_file) {
        ist = std::ifstream{ input_file };
        if (!ist) {
            std::cout << "Cannot open: " << input_file << std::endl;
            return 0;
        }
    }
     
    std::ofstream ost;
    if (is_output_file) {
        ost = std::ofstream{ output_file };
        if (!ost) {
            std::cout << "Cannot open: " << output_file << std::endl;
            return 0;
        }
    }
    std::ofstream timings_oft;
    if (is_hash_size) {
        timings_oft = std::ofstream{"timings.txt"};
        if (!timings_oft) {
            std::cout << "Cannot open: timings.txt\n";
            return 0;
        }
    }

    std::string msg;
    std::ostream* out = is_output_file ? &ost : &std::cout;
    sha3::hash hash;

    while (true) {
        std::getline(ist, msg);

        if (ist) {
            if (!is_hash_size) {
                all_hashes(msg, *out, keccakf);
            } else {
                if (is_hash_size) {
                    auto t1 = Clock::now();
                    hash = sha3::make_hash(msg, sha3_len, keccakf);
                    auto t2 = Clock::now();
                    timings_oft << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << "\n";
                    *out << hash << "\n";
                }
                else {
                    hash = sha3::make_hash(msg, sha3_len, keccakf);
                    *out << hash << "\n";
                }
            }
        }

        if (ist.eof())
            break;

        if (ist.bad()) {
            std::cout << "error parsing file.\n";
            return 0;
        }
    }

	return 0;
}

int getopt(int argc, char* const argv[], const char* optstring)
{
    if ((optind >= argc) || (argv[optind][0] != '-') || (argv[optind][0] == 0))
    {
        return -1;
    }

    int opt = argv[optind][1];
    const char* p = strchr(optstring, opt);

    if (p == NULL)
    {
        return '?';
    }
    if (p[1] == ':')
    {
        optind++;
        if (optind >= argc)
        {
            return '?';
        }
        optarg = argv[optind];
        optind++;
    }
    return opt;
}
