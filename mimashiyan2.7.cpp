#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

std::string pkcs7_unpad(const std::string& data) {
    if (data.empty()) {
        throw std::invalid_argument("Data is empty");
    }

    unsigned char pad_len = static_cast<unsigned char>(data.back());

    // 验证填充长度是否有效（1-16之间）
    if (pad_len < 1 || pad_len > 16) {
        throw std::invalid_argument("Invalid padding length");
    }

    // 验证填充长度是否超过数据长度
    if (pad_len > data.size()) {
        throw std::invalid_argument("Padding length exceeds data size");
    }

    // 验证填充内容是否正确
    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (static_cast<unsigned char>(data[i]) != pad_len) {
            throw std::invalid_argument("Invalid padding bytes");
        }
    }

    // 返回去除填充后的数据
    return data.substr(0, data.size() - pad_len);
}

int main() {
    try {
        // 测试1：正确的填充
        std::string test1 = "ICE ICE BABY\x04\x04\x04\x04";
        std::string result1 = pkcs7_unpad(test1);
        std::cout << "Test 1 (valid): " << result1 << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << "Test 1: " << e.what() << std::endl;
    }

    try {
        // 测试2：错误的填充（全为\x05但只有4个字节）
        std::string test2 = "ICE ICE BABY\x05\x05\x05\x05";
        std::string result2 = pkcs7_unpad(test2);
        std::cout << "Test 2 (invalid): " << result2 << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << "Test 2: ValueError (Invalid padding bytes)" << std::endl;
    }

    try {
        // 测试3：填充字节不一致
        std::string test3 = "ICE ICE BABY\x01\x02\x03\x04";
        std::string result3 = pkcs7_unpad(test3);
        std::cout << "Test 3 (invalid): " << result3 << std::endl;

    }
    catch (const std::exception& e) {
        std::cout << "Test 3: ValueError (Invalid padding bytes)" << std::endl;
    }

    return 0;
}