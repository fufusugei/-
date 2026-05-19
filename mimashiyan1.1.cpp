#include <iostream>
#include <string>
#include <vector>

// Base64 字符表
const std::string base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 将 16 进制字符转成对应的数字
unsigned char hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// 将 16 进制字符串转成字节数组
std::vector<unsigned char> hexStringToBytes(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    if (hexStr.length() % 2 != 0) return bytes; // 非偶数返回空
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        unsigned char byte = (hexCharToByte(hexStr[i]) << 4) | hexCharToByte(hexStr[i + 1]);
        bytes.push_back(byte);
    }
    return bytes;
}

// Base64 编码函数
std::string base64Encode(const std::vector<unsigned char>& data) {
    std::string encoded;
    size_t len = data.size();
    for (size_t i = 0; i < len; i += 3) {
        unsigned int octet_a = i < len ? data[i] : 0;
        unsigned int octet_b = (i + 1) < len ? data[i + 1] : 0;
        unsigned int octet_c = (i + 2) < len ? data[i + 2] : 0;

        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded += base64_table[(triple >> 18) & 0x3F];
        encoded += base64_table[(triple >> 12) & 0x3F];
        encoded += (i + 1) < len ? base64_table[(triple >> 6) & 0x3F] : '=';
        encoded += (i + 2) < len ? base64_table[triple & 0x3F] : '=';
    }
    return encoded;
}

int main() {
    std::string hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    std::vector<unsigned char> bytes = hexStringToBytes(hexStr);
    if (bytes.empty()) {
        std::cout << "无效的16进制字符串" << std::endl;
        return 1;
    }

    std::string base64Str = base64Encode(bytes);
    std::cout << "Base64 编码结果:\n" << base64Str << std::endl;

    return 0;
}