#include <iostream>
#include <string>
#include <iomanip>

std::string pkcs7_pad(const std::string& data, size_t block_size) {
    size_t pad_len = block_size - (data.size() % block_size);
    if (pad_len == 0) pad_len = block_size;

    std::string padded = data;
    padded.append(pad_len, static_cast<char>(pad_len));
    return padded;
}

int main() {
    std::string data = "YELLOW SUBMARINE";
    std::string padded = pkcs7_pad(data, 20);

    std::cout << "PKCS#7 padded: ";
    for (unsigned char c : padded) {
        if (c >= 32 && c <= 126) {
            std::cout << c;
        }
        else {
            std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(c) << std::dec;
        }
    }
    std::cout << std::endl;

    return 0;
}