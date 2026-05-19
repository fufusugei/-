#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <sstream>
#include <iomanip>

// 十六进制字符转字节
unsigned char hexCharToByte(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    return std::tolower(c) - 'a' + 10;
}

// 十六进制字符串转字节数组
std::vector<unsigned char> hexStringToBytes(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    if (hexStr.length() % 2 != 0) return bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        unsigned char byte = (hexCharToByte(hexStr[i]) << 4) | hexCharToByte(hexStr[i + 1]);
        bytes.push_back(byte);
    }
    return bytes;
}

// 统计字母和空格数量，作为评分标准
int scoreText(const std::string& text) {
    int score = 0;
    for (char c : text) {
        if (std::isalpha(c) || c == ' ') score++;
    }
    return score;
}

int main() {
    std::ifstream infile("4.txt"); // 输入文件
    if (!infile) {
        std::cerr << "无法打开文件 4.txt" << std::endl;
        return 1;
    }

    std::vector<std::string> wenben;
    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty() && line.back() == '\n') line.pop_back();
        wenben.push_back(line);
    }

    int max_score = 0;
    std::string best_ans;
    std::string best_c;
    char best_key = 0;

    // 遍历文件每一行
    for (const auto& k : wenben) {
        std::vector<unsigned char> bytes = hexStringToBytes(k);
        if (bytes.empty()) continue;

        // 尝试 0~128 的单字节密钥
        for (int i = 0; i < 129; ++i) {
            std::string tmp_str;
            for (auto b : bytes) {
                tmp_str += b ^ i;
            }

            int current_score = scoreText(tmp_str);

            if (current_score > max_score) {
                max_score = current_score;
                best_ans = tmp_str;
                best_c = k;
                best_key = static_cast<char>(i);
            }
        }
    }

    std::cout << "最佳密文行: " << best_c << std::endl;
    std::cout << "最佳密钥: " << best_key << std::endl;
    std::cout << "解密结果: " << best_ans << std::endl;

    return 0;
}