#ifndef RCXX_HPP
#define RCXX_HPP

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <string>
#include <stdexcept>
#include <vector>
#include <algorithm>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard [[nodiscard]]
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept const noexcept

class __attr_hot RCUtils {
public:
    // Secure random bytes
    static void get_secure_random_bytes(void *buf, size_t len) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (unlikely(fd < 0)) {
            perror("open /dev/urandom");
            throw std::runtime_error("Failed to open /dev/urandom");
        }
        ssize_t r = read(fd, buf, len);
        if (unlikely(r != (ssize_t)len)) {
            perror("read /dev/urandom");
            close(fd);
            throw std::runtime_error("Failed to read /dev/urandom");
        }
        close(fd);
    }

    // Hex encoding/decoding
    static std::string ToHex(const std::string& data) __noexcept {
        static const char hex_digits[] = "0123456789abcdef";
        std::string out(data.size() * 2, '0');
        for (size_t i = 0; i < data.size(); ++i) {
            out[2*i] = hex_digits[(uint8_t(data[i]) >> 4) & 0xF];
            out[2*i+1] = hex_digits[uint8_t(data[i]) & 0xF];
        }
        return out;
    }
    __attr_nodiscard
    static std::string FromHex(const std::string& hex) __noexcept {
        if (hex.size() % 2 != 0) return {};
        std::string out(hex.size() / 2, '\0');
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned int byte;
            if (sscanf(hex.data() + i, "%2x", &byte) != 1) return {};
            out[i / 2] = static_cast<char>(byte);
        }
        return out;
    }
};

// ================= RC2 ===================
class __attr_hot RC2 {
public:
    static constexpr size_t BLOCK_SIZE = 8;

    RC2() { std::fill(std::begin(K), std::end(K), 0); }

    __attr_nodiscard
    std::string Encrypt(const std::string& plaintext, const std::string& key) {
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size());
        size_t ptlen = plaintext.size();
        size_t num_blocks = (ptlen + BLOCK_SIZE - 1) / BLOCK_SIZE;
        std::string ciphertext(num_blocks * BLOCK_SIZE, '\0');

        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE] = {0};
            size_t block_len = std::min(BLOCK_SIZE, ptlen - i * BLOCK_SIZE);
            if (block_len > 0)
                memcpy(block, plaintext.data() + i * BLOCK_SIZE, block_len);
            BlockEncrypt(block);
            memcpy(&ciphertext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return ciphertext;
    }

    __attr_nodiscard
    std::string Decrypt(const std::string& ciphertext, const std::string& key) {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC2: ciphertext length not multiple of block size");
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size());
        size_t num_blocks = ciphertext.size() / BLOCK_SIZE;
        std::string plaintext(ciphertext.size(), '\0');
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, ciphertext.data() + i * BLOCK_SIZE, BLOCK_SIZE);
            BlockDecrypt(block);
            memcpy(&plaintext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return plaintext;
    }

private:
    uint16_t K[64];

    void KeyExpand(const uint8_t* key, size_t keylen) __noexcept {
        static const uint8_t PI_SUBST[256] = {
            217,120,249,196,25,221,181,237,40,233,253,121,74,160,216,157,198,126,55,131,43,118,83,142,98,76,100,136,68,139,251,162,
            23,154,89,245,135,179,79,19,97,69,109,141,9,129,125,50,189,143,64,235,134,183,123,11,240,149,33,34,92,107,78,130,
            84,214,101,147,206,96,178,28,115,86,192,20,167,140,241,220,18,186,247,120,234,75,0,26,197,62,94,252,219,203,117,35,
            11,32,57,177,33,88,237,149,56,87,174,20,125,136,149,14,157,46,137,240,13,236,141,60,82,13,183,160,160,223,224,217,
            95,112,128,154,107,221,224,124,155,197,255,135,144,251,183,142,115,189,218,157,61,114,175,188,24,88,69,222,179,20,143,234,
            198,93,34,178,203,131,33,135,139,233,139,49,55,99,212,213,38,237,101,73,125,149,54,172,251,227,14,50,113,221,27,63,
            46,221,99,169,197,115,77,193,34,106,59,86,170,24,38,176,238,87,132,10,242,92,190,211,91,219,194,146,76,120,215,107,
            60,241,82,62,2,129,41,159,36,205,111,41,244,224,21,37,136,101,63,20,153,243,234,49,102,222,110,78,161,172,54,99
        };
        uint8_t L[128] = {0};
        size_t T = keylen;
        memcpy(L, key, T);
        for (size_t i = T; i < 128; ++i)
            L[i] = PI_SUBST[(L[i-1] + L[i-T]) & 0xFF];
        for (size_t i = 0; i < 64; ++i)
            K[i] = L[2*i] + (L[2*i+1] << 8);
    }

    void BlockEncrypt(uint8_t* block) const __noexcept {
        uint16_t x[4];
        for (int i = 0; i < 4; ++i)
            x[i] = block[2*i] + (block[2*i+1] << 8);
        int j = 0;
        for (int r = 0; r < 16; ++r) {
            x[0] = (x[0] + ((x[1] & ~x[3]) + (x[2] & x[3]) + K[j++])) & 0xFFFF;
            x[0] = (x[0] << 1) | (x[0] >> 15);
            x[1] = (x[1] + ((x[2] & ~x[0]) + (x[3] & x[0]) + K[j++])) & 0xFFFF;
            x[1] = (x[1] << 2) | (x[1] >> 14);
            x[2] = (x[2] + ((x[3] & ~x[1]) + (x[0] & x[1]) + K[j++])) & 0xFFFF;
            x[2] = (x[2] << 3) | (x[2] >> 13);
            x[3] = (x[3] + ((x[0] & ~x[2]) + (x[1] & x[2]) + K[j++])) & 0xFFFF;
            x[3] = (x[3] << 5) | (x[3] >> 11);
            if (r == 4 || r == 10)
                for (int i = 0; i < 4; ++i)
                    x[i] = (x[i] + K[x[(i+3)%4] & 63]) & 0xFFFF;
        }
        for (int i = 0; i < 4; ++i) {
            block[2*i] = x[i] & 0xFF;
            block[2*i+1] = x[i] >> 8;
        }
    }

    void BlockDecrypt(uint8_t* block) const __noexcept {
        uint16_t x[4];
        for (int i = 0; i < 4; ++i)
            x[i] = block[2*i] + (block[2*i+1] << 8);
        int j = 63;
        for (int r = 15; r >= 0; --r) {
            if (r == 4 || r == 10)
                for (int i = 3; i >= 0; --i)
                    x[i] = (x[i] - K[x[(i+3)%4] & 63]) & 0xFFFF;
            x[3] = ((x[3] >> 5) | (x[3] << 11)) & 0xFFFF;
            x[3] = (x[3] - ((x[0] & ~x[2]) + (x[1] & x[2]) + K[j--])) & 0xFFFF;
            x[2] = ((x[2] >> 3) | (x[2] << 13)) & 0xFFFF;
            x[2] = (x[2] - ((x[3] & ~x[1]) + (x[0] & x[1]) + K[j--])) & 0xFFFF;
            x[1] = ((x[1] >> 2) | (x[1] << 14)) & 0xFFFF;
            x[1] = (x[1] - ((x[2] & ~x[0]) + (x[3] & x[0]) + K[j--])) & 0xFFFF;
            x[0] = ((x[0] >> 1) | (x[0] << 15)) & 0xFFFF;
            x[0] = (x[0] - ((x[1] & ~x[3]) + (x[2] & x[3]) + K[j--])) & 0xFFFF;
        }
        for (int i = 0; i < 4; ++i) {
            block[2*i] = x[i] & 0xFF;
            block[2*i+1] = x[i] >> 8;
        }
    }
};

// ================= RC4 ===================
class __attr_hot RC4 {
public:
    RC4() { std::fill(std::begin(S), std::end(S), 0); i = j = 0; }

    __attr_nodiscard
    std::string Encrypt(const std::string& plaintext, const std::string& key) {
        SetKey(reinterpret_cast<const uint8_t*>(key.data()), key.size());
        std::string ciphertext = plaintext;
        Process(reinterpret_cast<uint8_t*>(&ciphertext[0]), ciphertext.size());
        return ciphertext;
    }

    __attr_nodiscard
    std::string Decrypt(const std::string& ciphertext, const std::string& key) {
        SetKey(reinterpret_cast<const uint8_t*>(key.data()), key.size());
        std::string plaintext = ciphertext;
        Process(reinterpret_cast<uint8_t*>(&plaintext[0]), plaintext.size());
        return plaintext;
    }

private:
    uint8_t S[256], i, j;
    void SetKey(const uint8_t* key, size_t keylen) __noexcept {
        for (int idx = 0; idx < 256; ++idx)
            S[idx] = (uint8_t)idx;
        uint8_t j0 = 0;
        for (int idx = 0; idx < 256; ++idx) {
            j0 += S[idx] + key[idx % keylen];
            std::swap(S[idx], S[j0]);
        }
        i = j = 0;
    }
    void Process(uint8_t* data, size_t length) __noexcept {
        uint8_t ii = i, jj = j;
        for (size_t k = 0; k < length; ++k) {
            ii = ii + 1;
            jj = jj + S[ii];
            std::swap(S[ii], S[jj]);
            data[k] ^= S[(S[ii] + S[jj]) & 0xFF];
        }
        i = ii;
        j = jj;
    }
};

// ================= RC5 ===================
class __attr_hot RC5 {
public:
    static constexpr size_t BLOCK_SIZE = 8;
    RC5() { std::fill(std::begin(S), std::end(S), 0); rounds = 0; }

    __attr_nodiscard
    std::string Encrypt(const std::string& plaintext, const std::string& key, uint32_t r = 12) {
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size(), r);
        size_t ptlen = plaintext.size();
        size_t num_blocks = (ptlen + BLOCK_SIZE - 1) / BLOCK_SIZE;
        std::string ciphertext(num_blocks * BLOCK_SIZE, '\0');
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE] = {0};
            size_t block_len = std::min(BLOCK_SIZE, ptlen - i * BLOCK_SIZE);
            if (block_len > 0)
                memcpy(block, plaintext.data() + i * BLOCK_SIZE, block_len);
            BlockEncrypt(block);
            memcpy(&ciphertext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return ciphertext;
    }

    __attr_nodiscard
    std::string Decrypt(const std::string& ciphertext, const std::string& key, uint32_t r = 12) {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC5: ciphertext length not multiple of block size");
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size(), r);
        size_t num_blocks = ciphertext.size() / BLOCK_SIZE;
        std::string plaintext(ciphertext.size(), '\0');
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, ciphertext.data() + i * BLOCK_SIZE, BLOCK_SIZE);
            BlockDecrypt(block);
            memcpy(&plaintext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return plaintext;
    }

private:
    uint32_t S[26];
    uint32_t rounds;

    static uint32_t rotl(uint32_t x, uint32_t y) __noexcept { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
    static uint32_t rotr(uint32_t x, uint32_t y) __noexcept { return (x >> (y & 31)) | (x << (32 - (y & 31))); }

    void KeyExpand(const uint8_t* key, size_t keylen, uint32_t r) {
        const uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
        size_t Llen = (keylen+3)/4;
        std::vector<uint32_t> L(Llen ? Llen : 1, 0);
        for (int i = keylen-1; i >= 0; --i)
            L[i/4] = (L[i/4] << 8) + key[i];
        S[0] = Pw;
        for (size_t i = 1; i < 2*r+2; ++i)
            S[i] = S[i-1] + Qw;
        uint32_t A = 0, B = 0, i = 0, j = 0, v = 3 * (Llen > (2*r+2) ? Llen : (2*r+2));
        for (uint32_t s = 0; s < v; ++s) {
            A = S[i] = rotl(S[i] + A + B, 3);
            B = L[j] = rotl(L[j] + A + B, (A+B));
            i = (i+1) % (2*r+2);
            j = (j+1) % Llen;
        }
        rounds = r;
    }
    void BlockEncrypt(uint8_t* block) const __noexcept {
        uint32_t A, B;
        memcpy(&A, block, 4);
        memcpy(&B, block+4, 4);
        A += S[0]; B += S[1];
        for (uint32_t i = 1; i <= rounds; ++i) {
            A = rotl(A ^ B, B) + S[2*i];
            B = rotl(B ^ A, A) + S[2*i+1];
        }
        memcpy(block, &A, 4);
        memcpy(block+4, &B, 4);
    }
    void BlockDecrypt(uint8_t* block) const __noexcept {
        uint32_t A, B;
        memcpy(&A, block, 4);
        memcpy(&B, block+4, 4);
        for (uint32_t i = rounds; i >= 1; --i) {
            B = rotr(B - S[2*i+1], A) ^ A;
            A = rotr(A - S[2*i], B) ^ B;
        }
        B -= S[1]; A -= S[0];
        memcpy(block, &A, 4);
        memcpy(block+4, &B, 4);
    }
};

// ================= RC6 ===================
class __attr_hot RC6 {
public:
    static constexpr size_t BLOCK_SIZE = 16;
    RC6() { std::fill(std::begin(S), std::end(S), 0); rounds = 0; }

    __attr_nodiscard
    std::string Encrypt(const std::string& plaintext, const std::string& key, uint32_t r = 20) {
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size(), r);
        size_t ptlen = plaintext.size();
        size_t num_blocks = (ptlen + BLOCK_SIZE - 1) / BLOCK_SIZE;
        std::string ciphertext(num_blocks * BLOCK_SIZE, '\0');
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE] = {0};
            size_t block_len = std::min(BLOCK_SIZE, ptlen - i * BLOCK_SIZE);
            if (block_len > 0)
                memcpy(block, plaintext.data() + i * BLOCK_SIZE, block_len);
            BlockEncrypt(block);
            memcpy(&ciphertext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return ciphertext;
    }

    __attr_nodiscard
    std::string Decrypt(const std::string& ciphertext, const std::string& key, uint32_t r = 20) {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC6: ciphertext length not multiple of block size");
        KeyExpand(reinterpret_cast<const uint8_t*>(key.data()), key.size(), r);
        size_t num_blocks = ciphertext.size() / BLOCK_SIZE;
        std::string plaintext(ciphertext.size(), '\0');
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t block[BLOCK_SIZE];
            memcpy(block, ciphertext.data() + i * BLOCK_SIZE, BLOCK_SIZE);
            BlockDecrypt(block);
            memcpy(&plaintext[i * BLOCK_SIZE], block, BLOCK_SIZE);
        }
        return plaintext;
    }

private:
    uint32_t S[44];
    uint32_t rounds;

    static uint32_t rotl(uint32_t x, uint32_t y) __noexcept { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
    static uint32_t rotr(uint32_t x, uint32_t y) __noexcept { return (x >> (y & 31)) | (x << (32 - (y & 31))); }
    static uint32_t get_u32(const uint8_t* b) __noexcept {
        return ((uint32_t)b[0]) | (((uint32_t)b[1]) << 8) | (((uint32_t)b[2]) << 16) | (((uint32_t)b[3]) << 24);
    }
    static void set_u32(uint8_t* b, uint32_t v) __noexcept {
        b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF; b[3] = (v >> 24) & 0xFF;
    }

    void KeyExpand(const uint8_t* key, size_t keylen, uint32_t r) {
        const uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
        size_t Llen = (keylen+3)/4;
        std::vector<uint32_t> L(Llen ? Llen : 1, 0);
        for (int i = keylen-1; i >= 0; --i)
            L[i/4] = (L[i/4] << 8) + key[i];
        S[0] = Pw;
        for (size_t i = 1; i < 44; ++i)
            S[i] = S[i-1] + Qw;
        uint32_t A = 0, B = 0, i = 0, j = 0, v = 3*(Llen > 44 ? Llen : 44);
        for (uint32_t s = 0; s < v; ++s) {
            A = S[i] = rotl(S[i] + A + B, 3);
            B = L[j] = rotl(L[j] + A + B, (A+B));
            i = (i+1) % 44;
            j = (j+1) % Llen;
        }
        rounds = r;
    }
    void BlockEncrypt(uint8_t* block) const __noexcept {
        uint32_t A = get_u32(block);
        uint32_t B = get_u32(block+4);
        uint32_t C = get_u32(block+8);
        uint32_t D = get_u32(block+12);
        B += S[0];
        D += S[1];
        for (uint32_t i = 1; i <= rounds; ++i) {
            uint32_t t = rotl(B*(2*B+1), 5);
            uint32_t u = rotl(D*(2*D+1), 5);
            A = rotl(A^t, u) + S[2*i];
            C = rotl(C^u, t) + S[2*i+1];
            uint32_t tmp = A; A = B; B = C; C = D; D = tmp;
        }
        A += S[2*rounds+2];
        C += S[2*rounds+3];
        set_u32(block, A);
        set_u32(block+4, B);
        set_u32(block+8, C);
        set_u32(block+12, D);
    }
    void BlockDecrypt(uint8_t* block) const __noexcept {
        uint32_t A = get_u32(block);
        uint32_t B = get_u32(block+4);
        uint32_t C = get_u32(block+8);
        uint32_t D = get_u32(block+12);
        C -= S[2*rounds+3];
        A -= S[2*rounds+2];
        for (int i = rounds; i >= 1; --i) {
            uint32_t tmp = D; D = C; C = B; B = A; A = tmp;
            uint32_t u = rotl(D*(2*D+1), 5);
            uint32_t t = rotl(B*(2*B+1), 5);
            C = rotr(C - S[2*i+1], t) ^ u;
            A = rotr(A - S[2*i], u) ^ t;
        }
        D -= S[1];
        B -= S[0];
        set_u32(block, A);
        set_u32(block+4, B);
        set_u32(block+8, C);
        set_u32(block+12, D);
    }
};

#endif // RCXX_HPP
