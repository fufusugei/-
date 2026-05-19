#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <regex>

// 将十六进制字符串转换为字节数组
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// 单字节XOR解密，返回字符串
std::string singleByteXOR(const std::vector<unsigned char>& cipher, unsigned char key) {
    std::string result;
    for (unsigned char c : cipher) {
        result += static_cast<char>(c ^ key);
    }
    return result;
}

// 统计字符串中字母和空格的数量
int countLettersAndSpaces(const std::string& text) {
    int count = 0;
    for (char c : text) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (std::isalpha(uc) || uc == ' ') {
            count++;
        }
    }
    return count;
}

int main() {
    std::ifstream infile("input.txt");
    if (!infile.is_open()) {
        std::cerr << "错误：无法打开 input.txt 文件" << std::endl;
        return 1;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(infile, line)) {
        // 去除可能的回车符
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    infile.close();

    int maxScore = 0;
    std::string bestAns;
    std::string bestCipher;
    unsigned char bestKey = 0;

    // 遍历每一行密文
    for (const auto& cipherHex : lines) {
        // 转换为字节数组
        std::vector<unsigned char> cipherBytes = hexToBytes(cipherHex);

        // 尝试所有可能的密钥 (0-128，与Python代码一致)
        for (int key = 0; key <= 128; ++key) {
            std::string plaintext = singleByteXOR(cipherBytes, static_cast<unsigned char>(key));
            int currentScore = countLettersAndSpaces(plaintext);

            if (currentScore > maxScore) {
                maxScore = currentScore;
                bestAns = plaintext;
                bestCipher = cipherHex;
                bestKey = static_cast<unsigned char>(key);
            }
        }
    }

    // 输出结果
    std::cout << "最佳密文: " << bestCipher << std::endl;
    std::cout << "最佳密钥: " << static_cast<int>(bestKey);
    // 如果密钥是可打印字符，显示字符形式
    if (std::isprint(bestKey)) {
        std::cout << " ('" << bestKey << "')";
    }
    std::cout << std::endl;
    std::cout << "解密结果: " << bestAns << std::endl;
    std::cout << "得分(字母+空格数量): " << maxScore << std::endl;

    return 0;
}