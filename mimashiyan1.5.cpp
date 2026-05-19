#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

// 重复密钥 XOR
std::string xorRepeatKey(const std::string& key, const std::string& text) {
    std::string result;
    size_t keyLen = key.length();

    for (size_t i = 0; i < text.length(); ++i) {
        char b = text[i] ^ key[i % keyLen];
        result += b;
    }
    return result;
}

// 将字符串转换为十六进制字符串
std::string toHexString(const std::string& input) {
    std::ostringstream oss;
    for (unsigned char c : input) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

int main() {
    std::string string1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    std::string key = "ICE";

    std::string encrypted = xorRepeatKey(key, string1);
    std::string hexResult = toHexString(encrypted);

    std::cout << hexResult << std::endl;

    return 0;
}