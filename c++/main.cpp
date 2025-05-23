#include "rc.hpp"
#include <iostream>
#include <iomanip>

// Helper to print hex
std::string to_hex(const std::string& data) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : data) {
        out += hex[(c >> 4) & 0xF];
        out += hex[c & 0xF];
    }
    return out;
}

void test_rc2() {
    std::string key = "keyRC2";
    std::string plain = "Secret message for RC2!";

    RC2 rc2;
    std::string cipher = rc2.Encrypt(plain, key);
    std::string decrypted = rc2.Decrypt(cipher, key);

    std::cout << "[RC2] Original:   " << plain << '\n';
    std::cout << "[RC2] Cipher(hex): " << to_hex(cipher) << '\n';
    std::cout << "[RC2] Decrypted:  " << decrypted << "\n\n";
}

void test_rc4() {
    std::string key = "keyRC4";
    std::string plain = "Secret message for RC4!";

    RC4 rc4;
    std::string cipher = rc4.Encrypt(plain, key);
    std::string decrypted = rc4.Decrypt(cipher, key);

    std::cout << "[RC4] Original:   " << plain << '\n';
    std::cout << "[RC4] Cipher(hex): " << to_hex(cipher) << '\n';
    std::cout << "[RC4] Decrypted:  " << decrypted << "\n\n";
}

void test_rc5() {
    std::string key = "keyRC5";
    std::string plain = "Secret message for RC5!";

    RC5 rc5;
    std::string cipher = rc5.Encrypt(plain, key); // default rounds=12
    std::string decrypted = rc5.Decrypt(cipher, key);

    std::cout << "[RC5] Original:   " << plain << '\n';
    std::cout << "[RC5] Cipher(hex): " << to_hex(cipher) << '\n';
    std::cout << "[RC5] Decrypted:  " << decrypted << "\n\n";
}

void test_rc6() {
    std::string key = "keyRC6";
    std::string plain = "Secret message for RC6!";

    RC6 rc6;
    std::string cipher = rc6.Encrypt(plain, key); // default rounds=20
    std::string decrypted = rc6.Decrypt(cipher, key);

    std::cout << "[RC6] Original:   " << plain << '\n';
    std::cout << "[RC6] Cipher(hex): " << to_hex(cipher) << '\n';
    std::cout << "[RC6] Decrypted:  " << decrypted << "\n\n";
}

int main() {
    try {
        test_rc2();
        test_rc4();
        test_rc5();
        test_rc6();
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        return 1;
    }
    return 0;
}
