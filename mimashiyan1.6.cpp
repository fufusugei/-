#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <sstream>
#include <map>

// Base64 解码表
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::vector<unsigned char> base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0, j = 0, in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

// 计算英文评分
double english_score(const std::string& text) {
    std::map<char, double> freqs = {
        {'a',0.0651738},{'b',0.0124248},{'c',0.0217339},{'d',0.0349835},{'e',0.1041442},
        {'f',0.0197881},{'g',0.0158610},{'h',0.0492888},{'i',0.0558094},{'j',0.0009033},
        {'k',0.0050529},{'l',0.0331490},{'m',0.0202124},{'n',0.0564513},{'o',0.0596302},
        {'p',0.0137645},{'q',0.0008606},{'r',0.0497563},{'s',0.0515760},{'t',0.0729357},
        {'u',0.0225134},{'v',0.0082903},{'w',0.0171272},{'x',0.0013692},{'y',0.0145984},
        {'z',0.0007836},{' ',0.1918182}
    };
    double score = 0.0;
    for (auto c : text) {
        c = tolower(c);
        if (freqs.find(c) != freqs.end()) score += freqs[c];
    }
    return score;
}

// 汉明距离
int hamming_distance(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    int dist = 0;
    size_t len = std::min(a.size(), b.size());
    for (size_t i = 0; i < len; i++) {
        unsigned char x = a[i] ^ b[i];
        while (x) {
            dist += x & 1;
            x >>= 1;
        }
    }
    return dist;
}

// 找单字节密钥
unsigned char single_byte_xor_key(const std::vector<unsigned char>& bytes) {
    double max_score = -1.0;
    unsigned char best_key = 0;
    for (int k = 0; k < 256; k++) {
        std::string decoded;
        for (auto b : bytes)
            decoded += char(b ^ k);
        double score = english_score(decoded);
        if (score > max_score) {
            max_score = score;
            best_key = k;
        }
    }
    return best_key;
}

int main() {
    std::ifstream fin("cipher.txt");
    if (!fin) {
        std::cerr << "无法打开 cipher.txt 文件\n";
        return 1;
    }

    std::string line, base64_text;
    while (std::getline(fin, line)) {
        base64_text += line;
    }
    fin.close();

    std::vector<unsigned char> cipher_bytes = base64_decode(base64_text);

    // 假设密钥长度为 29 (可用汉明距离方法分析)
    const int key_length = 29;
    std::vector<unsigned char> key(key_length);

    // 将密文分列，找到每列的最佳单字节密钥
    for (int i = 0; i < key_length; i++) {
        std::vector<unsigned char> column;
        for (size_t j = i; j < cipher_bytes.size(); j += key_length) {
            column.push_back(cipher_bytes[j]);
        }
        key[i] = single_byte_xor_key(column);
    }

    std::cout << "找到的密钥: ";
    for (auto k : key) std::cout << k;
    std::cout << "\n";

    // 解密
    std::string plaintext;
    for (size_t i = 0; i < cipher_bytes.size(); i++) {
        plaintext += char(cipher_bytes[i] ^ key[i % key_length]);
    }

    std::cout << "\n解密结果:\n";
    std::cout << plaintext << "\n";

    return 0;
}