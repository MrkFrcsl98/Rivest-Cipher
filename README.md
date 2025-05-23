# RC Ciphers Library
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17 Ready](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![RSA Algorithm](https://img.shields.io/badge/algorithm-RSA-lightgrey.svg)](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
[![Key Sizes: Customizable](https://img.shields.io/badge/key%20sizes-customizable-green.svg)](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation)
[![Asymmetric Encryption](https://img.shields.io/badge/type-asymmetric-important.svg)](https://en.wikipedia.org/wiki/Public-key_cryptography)
[![Header-only](https://img.shields.io/badge/header--only-yes-critical.svg)](https://github.com/MrkFrcsl98/Rivest-Cipher)
[![Status: Educational](https://img.shields.io/badge/status-educational-important.svg)](#security-notes)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20C%2B%2B-blue)

A fast, portable, and easy-to-use implementation of the classic RC cryptographic ciphers (RC2, RC4, RC5, RC6) provided in both C and C++ header-only libraries.

---

## Table of Contents

- [Overview](#overview)
- [RC Cipher Family: History](#rc-cipher-family-history)
- [Supported Ciphers & Algorithms](#supported-ciphers--algorithms)
  - [RC2](#rc2)
  - [RC4](#rc4)
  - [RC5](#rc5)
  - [RC6](#rc6)
- [Library Versions](#library-versions)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
  - [C Version](#c-version)
  - [C++ Version](#c-version)
- [Detailed Cipher Documentation](#detailed-cipher-documentation)
  - [RC2 In-Depth](#rc2-in-depth)
  - [RC4 In-Depth](#rc4-in-depth)
  - [RC5 In-Depth](#rc5-in-depth)
  - [RC6 In-Depth](#rc6-in-depth)
- [Performance Notes](#performance-notes)
- [License](#license)
- [References](#references)

---

## Overview

This repository provides implementations of Ronald Rivest’s RC (Rivest Cipher, or Ron’s Code) family of encryption algorithms: RC2, RC4, RC5, and RC6, in both C and modern C++ (header-only) styles. The C version prioritizes maximum performance and bare-metal efficiency, while the C++ version offers a user-friendly, object-oriented API with `std::string` support for rapid prototyping, education, and ease of use.

---

## RC Cipher Family: History

The RC (Rivest Cipher or Ron’s Code) algorithms were developed by Ronald L. Rivest between the 1980s and 1990s:

- **RC2 (1987):** Designed as a block cipher to replace DES, with variable key sizes, and optimized for software.
- **RC4 (1987):** A stream cipher used widely in protocols like SSL/TLS and WEP/WPA for wireless security due to its speed and simplicity.
- **RC5 (1994):** Introduces variable block sizes, variable key sizes, and variable rounds, along with heavy use of data-dependent rotations.
- **RC6 (1998):** An evolution of RC5, designed as a candidate for the AES competition, featuring 128-bit blocks and more complex operations.

Each RC algorithm improved upon its predecessor, introducing new cryptographic principles and optimizations for hardware and software platforms.

---

## Supported Ciphers & Algorithms

### RC2

- Block cipher with 8-byte (64-bit) blocks.
- Variable key size (up to 128 bits typically).
- 16 rounds of complex mixing and mashing operations.
- Notable for its use in legacy applications and backward compatibility.

### RC4

- Stream cipher, not a block cipher.
- Variable key size (1 to 256 bytes).
- Simple and fast, but now deprecated in secure applications due to vulnerabilities.
- Used in SSL, WEP, and other protocols (now considered obsolete).

### RC5

- Block cipher with variable block size (32, 64, or 128 bits; library uses 64-bit blocks).
- Variable number of rounds (default: 12).
- Variable key sizes.
- Features heavy use of data-dependent rotations and modular addition.

### RC6

- Block cipher, always 128-bit blocks.
- Uses four 32-bit words per block.
- Variable key size and rounds (default: 20).
- Uses integer multiplication and additional mixing for improved security.
- AES finalist.

---

## Library Versions

| Version | Filename   | Language | API Style | Use Case                | Notes                        |
|---------|------------|----------|-----------|-------------------------|------------------------------|
| C       | `rc.h`     | C        | Procedural| Maximum speed, embedded | Fastest, low-level           |
| C++     | `rc.hpp` | C++17+   | OOP, STL  | User-friendly, modern   | Easy for beginners, flexible |

- **Prefer the C version (`rc.h`)** for performance-critical or embedded use.
- **Use the C++ version (`rc.hpp`)** for rapid development, education, or if you want a higher-level API.

---

## Installation

1. **Add the header file you want:**
   - For C: Copy `rc.h` into your project.
   - For C++: Copy `rc.hpp` into your project.

2. **No library build step required:** Both versions are header-only.

---

## Usage Examples

### C Version

```c
#include "rc.h"
#include <stdio.h>
#include <string.h>

int main() {
    char key[] = "mykey";
    char plaintext[] = "Secret message!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];

    // RC2 Encrypt
    size_t ctlen = RC2_Encrypt(key, plaintext, ciphertext);
    // RC2 Decrypt
    size_t ptlen = RC2_Decrypt(key, ciphertext, ctlen, decrypted);

    printf("Original: %s\n", plaintext);
    printf("Encrypted (hex): ");
    char hex[256];
    to_hex(ciphertext, ctlen, hex);
    printf("%s\n", hex);

    printf("Decrypted: %.*s\n", (int)ptlen, decrypted);
    return 0;
}
```

### C++ Version

```cpp
#include "rc.hpp"
#include <iostream>

int main() {
    RC2 rc2;
    std::string key = "mykey";
    std::string plaintext = "Secret message!";

    std::string ciphertext = rc2.Encrypt(plaintext, key);
    std::string decrypted  = rc2.Decrypt(ciphertext, key);

    std::cout << "Original:   " << plaintext << std::endl;
    std::cout << "Encrypted (hex): " << RCUtils::ToHex(ciphertext) << std::endl;
    std::cout << "Decrypted:  " << decrypted << std::endl;
    return 0;
}
```

---

## Detailed Cipher Documentation

### RC2 In-Depth

- **Block cipher** with 64-bit blocks and variable key size (typically up to 128 bits).
- **Rounds:** 16, divided into MIX and MASH phases.
- **Key Expansion:** The user key is expanded into 64 16-bit words using a fixed permutation table (PI_SUBST).
- **Encryption Process:**
  1. Input block split into 4 16-bit words.
  2. 16 rounds: Each round, words are mixed using modular addition, bitwise operations, and key words.
  3. After rounds 5 and 11, special key mixing ("mash") occurs using key words indexed by earlier state.
  4. Each word is rotated left by a different amount after mixing.
- **Security:** Designed as a DES replacement; considered safe for legacy but not for new systems.

### RC4 In-Depth

- **Stream cipher** with variable key size (1–256 bytes).
- **Key Scheduling:** Initializes a 256-byte state array, then permutes it based on the key.
- **Keystream Generation:** For each byte, two indexes are updated, S-box is swapped, and the output byte is selected.
- **Encryption:** XORs the keystream with the plaintext.
- **Security:** Once dominant but now considered broken due to biases in the keystream and weak key scheduling; not recommended for new applications.

### RC5 In-Depth

- **Block cipher** with variable block size (32, 64, or 128 bits), key size (0–2040 bits), and number of rounds (0–255).
- **Library default:** 64-bit blocks, 12 rounds.
- **Key Expansion:** User key is expanded into a set of round keys (S array) using modular arithmetic.
- **Encryption:**
  1. Input split into two words (A, B).
  2. Initial key mixing (A += S[0], B += S[1]).
  3. For each round:
      - A = ((A ^ B) <<< B) + S[2i]
      - B = ((B ^ A) <<< A) + S[2i+1]
  4. Output is (A, B).
- **Features:** Data-dependent rotations provide "avalanche" effect and resistance to differential cryptanalysis.
- **Security:** Flexible and strong if configured with enough rounds and a good key.

### RC6 In-Depth

- **Block cipher** with 128-bit (16-byte) blocks and variable key size (up to 256 bits).
- **Rounds:** Default 20 rounds.
- **Key Expansion:** Similar to RC5 but generates more subkeys (44 for 20 rounds).
- **Encryption:**
  1. Block split into four 32-bit words (A, B, C, D).
  2. Initial key mixing: B += S[0], D += S[1].
  3. For each round:
      - t = (B * (2B + 1)) <<< 5
      - u = (D * (2D + 1)) <<< 5
      - A = ((A ^ t) <<< u) + S[2i]
      - C = ((C ^ u) <<< t) + S[2i+1]
      - (A, B, C, D) = (B, C, D, A) (rotate variables)
  4. Final key mixing: A += S[2r+2], C += S[2r+3].
- **Security:** Designed as an AES finalist, more complex round function than RC5, and highly secure with a sufficient number of rounds.

---

## Performance Notes

- **C version (`rc.h`)**: Optimized for speed, with minimal abstraction and maximum portability. Recommended for high-performance applications, embedded systems, or cryptographic research.
- **C++ version (`rc.hpp`)**: Designed for ease of use, with a modern C++ interface, automatic block handling, and `std::string` support. Ideal for education, application prototyping, and high-level use.
