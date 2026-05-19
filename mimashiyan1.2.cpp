#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <sstream>
#include <iomanip>

// 将16进制字符转为整数
unsigned char hexCharToByte(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    return std::tolower(c) - 'a' + 10;
}

// 将16进制字符串转为字节数组
std::vector<unsigned char> hexStringToBytes(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    if (hexStr.length() % 2 != 0) return bytes;

    for (size_t i = 0; i < hexStr.length(); i += 2) {
        unsigned char byte = (hexCharToByte(hexStr[i]) << 4) | hexCharToByte(hexStr[i + 1]);
        bytes.push_back(byte);
    }
    return bytes;
}

// 将字节数组转回16进制字符串
std::string bytesToHexString(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    }
    return oss.str();
}

// XOR 函数：对输入字节数组和固定key进行异或
std::vector<unsigned char> xorWithKey(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        result[i] = data[i] ^ key[i % key.size()]; // key 可以循环使用
    }
    return result;
}

int main() {
    std::string hexInput;
    std::cout << "请输入16进制字符串: ";
    std::cin >> hexInput;

    // 固定key（示例，可根据需要修改）
    std::string keyHex = "686974207468652062756c6c277320657965";
    std::vector<unsigned char> keyBytes = hexStringToBytes(keyHex);

    std::vector<unsigned char> dataBytes = hexStringToBytes(hexInput);
    if (dataBytes.empty()) {
        std::cerr << "无效的16进制输入!" << std::endl;
        return 1;
    }

    std::vector<unsigned char> resultBytes = xorWithKey(dataBytes, keyBytes);
    std::string output = bytesToHexString(resultBytes);

    std::cout << "异或结果: " << output << std::endl;
    return 0;
}