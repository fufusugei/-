#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <random>
#include <stdexcept>
#include <cstring>

// ==================== AES-128 完整实现 ====================
class SimpleAES {
private:
    static const int Nb = 4;
    static const int Nk = 4;
    static const int Nr = 10;

    uint8_t roundKeys[11][4][4];

    static const uint8_t sbox[256];
    static const uint8_t inv_sbox[256];
    static const uint8_t rcon[11];

    static uint8_t gf256_mul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            bool carry = a & 0x80;
            a <<= 1;
            if (carry) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void subBytes(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = sbox[state[i][j]];
    }

    void invSubBytes(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = inv_sbox[state[i][j]];
    }

    void shiftRows(uint8_t state[4][4]) {
        uint8_t temp;
        temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
        temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
        temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
        temp = state[3][0]; state[3][0] = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = temp;
    }

    void invShiftRows(uint8_t state[4][4]) {
        uint8_t temp;
        temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
        temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
        temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
        temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;
    }

    void mixColumns(uint8_t state[4][4]) {
        uint8_t temp[4];
        for (int i = 0; i < 4; i++) {
            temp[0] = state[0][i];
            temp[1] = state[1][i];
            temp[2] = state[2][i];
            temp[3] = state[3][i];

            state[0][i] = gf256_mul(temp[0], 2) ^ gf256_mul(temp[1], 3) ^ temp[2] ^ temp[3];
            state[1][i] = temp[0] ^ gf256_mul(temp[1], 2) ^ gf256_mul(temp[2], 3) ^ temp[3];
            state[2][i] = temp[0] ^ temp[1] ^ gf256_mul(temp[2], 2) ^ gf256_mul(temp[3], 3);
            state[3][i] = gf256_mul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gf256_mul(temp[3], 2);
        }
    }

    void invMixColumns(uint8_t state[4][4]) {
        uint8_t temp[4];
        for (int i = 0; i < 4; i++) {
            temp[0] = state[0][i];
            temp[1] = state[1][i];
            temp[2] = state[2][i];
            temp[3] = state[3][i];

            state[0][i] = gf256_mul(temp[0], 0x0e) ^ gf256_mul(temp[1], 0x0b) ^ gf256_mul(temp[2], 0x0d) ^ gf256_mul(temp[3], 0x09);
            state[1][i] = gf256_mul(temp[0], 0x09) ^ gf256_mul(temp[1], 0x0e) ^ gf256_mul(temp[2], 0x0b) ^ gf256_mul(temp[3], 0x0d);
            state[2][i] = gf256_mul(temp[0], 0x0d) ^ gf256_mul(temp[1], 0x09) ^ gf256_mul(temp[2], 0x0e) ^ gf256_mul(temp[3], 0x0b);
            state[3][i] = gf256_mul(temp[0], 0x0b) ^ gf256_mul(temp[1], 0x0d) ^ gf256_mul(temp[2], 0x09) ^ gf256_mul(temp[3], 0x0e);
        }
    }

    void addRoundKey(uint8_t state[4][4], int round) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] ^= roundKeys[round][i][j];
    }

    void keyExpansion(const uint8_t* key) {
        uint8_t temp[4];
        for (int i = 0; i < Nk; i++) {
            roundKeys[0][i][0] = key[4 * i];
            roundKeys[0][i][1] = key[4 * i + 1];
            roundKeys[0][i][2] = key[4 * i + 2];
            roundKeys[0][i][3] = key[4 * i + 3];
        }

        for (int i = Nk; i < 4 * (Nr + 1); i++) {
            int col = i % 4;
            int row = i / 4;

            for (int j = 0; j < 4; j++)
                temp[j] = roundKeys[row - 1][col][j];

            if (col == 0) {
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                for (int j = 0; j < 4; j++)
                    temp[j] = sbox[temp[j]];

                temp[0] ^= rcon[row];
            }

            for (int j = 0; j < 4; j++)
                roundKeys[row][col][j] = roundKeys[row - 1][col][j] ^ temp[j];
        }
    }

public:
    SimpleAES(const uint8_t* key) {
        keyExpansion(key);
    }

    void encryptBlock(const uint8_t* input, uint8_t* output) {
        uint8_t state[4][4];

        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = input[i + 4 * j];

        addRoundKey(state, 0);

        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr);

        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                output[i + 4 * j] = state[i][j];
    }
};

// 静态成员初始化
const uint8_t SimpleAES::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t SimpleAES::inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint8_t SimpleAES::rcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// ==================== Base64 解码 ====================
std::string base64_decode(const std::string& in) {
    const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::vector<int> buf(4);
    int i = 0;
    for (char c : in) {
        if (c == '=') break;
        size_t pos = b64.find(c);
        if (pos == std::string::npos) continue;
        buf[i++] = pos;
        if (i == 4) {
            out.push_back((buf[0] << 2) | (buf[1] >> 4));
            out.push_back(((buf[1] & 0x0f) << 4) | (buf[2] >> 2));
            out.push_back(((buf[2] & 0x03) << 6) | buf[3]);
            i = 0;
        }
    }
    if (i > 0) {
        for (int j = i; j < 4; j++) buf[j] = 0;
        out.push_back((buf[0] << 2) | (buf[1] >> 4));
        if (i >= 3) out.push_back(((buf[1] & 0x0f) << 4) | (buf[2] >> 2));
        if (i >= 4) out.push_back(((buf[2] & 0x03) << 6) | buf[3]);
    }
    return out;
}

// ==================== 工具函数 ====================
std::string pkcs7_pad(const std::string& data, size_t block_size = 16) {
    size_t pad_len = block_size - (data.size() % block_size);
    if (pad_len == 0) pad_len = block_size;
    std::string padded = data;
    padded.append(pad_len, static_cast<char>(pad_len));
    return padded;
}

std::string pkcs7_unpad(const std::string& data) {
    if (data.empty()) return "";
    size_t pad_len = static_cast<unsigned char>(data.back());
    if (pad_len > data.size()) return data;
    return data.substr(0, data.size() - pad_len);
}

std::string aes_ecb_encrypt(const std::string& plaintext, const std::string& key) {
    if (plaintext.size() % 16 != 0) {
        throw std::runtime_error("Plaintext size must be multiple of 16");
    }
    SimpleAES aes(reinterpret_cast<const uint8_t*>(key.c_str()));
    std::string ciphertext(plaintext.size(), '\0');
    for (size_t i = 0; i < plaintext.size(); i += 16) {
        aes.encryptBlock(
            reinterpret_cast<const uint8_t*>(&plaintext[i]),
            reinterpret_cast<uint8_t*>(&ciphertext[i])
        );
    }
    return ciphertext;
}

// ==================== 主程序 ====================
int main() {
    try {
        // 初始化随机数生成器
        std::mt19937 rng(20260515);
        std::uniform_int_distribution<int> dist(0, 255);
        std::uniform_int_distribution<int> dist_len(5, 32);

        // 生成密钥和未知字符串
        std::string key(16, '\0');
        for (int i = 0; i < 16; i++) key[i] = dist(rng);

        std::string b64_unknown =
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK";
        std::string unknown = base64_decode(b64_unknown);

        // 生成随机前缀
        int prefix_len = dist_len(rng);
        std::string prefix(prefix_len, '\0');
        for (int i = 0; i < prefix_len; i++) prefix[i] = dist(rng);

        std::cout << "Prefix length: " << prefix_len << std::endl;

        // Oracle 函数
        auto oracle = [&](const std::string& data) -> std::string {
            return aes_ecb_encrypt(pkcs7_pad(prefix + data + unknown), key);
            };

        // 检测块大小
        size_t base_len = oracle("").size();
        size_t block_size = 0;
        for (size_t i = 1; i <= 64; i++) {
            std::string test(i, 'A');
            size_t len = oracle(test).size();
            if (len > base_len) {
                block_size = len - base_len;
                break;
            }
        }
        std::cout << "Block size: " << block_size << std::endl;

        // 找到重复块的位置
        int pad_len = -1, block_id = -1;
        for (int i = 0; i < (int)(block_size * 2); i++) {
            std::string input(i, 'A');
            input += std::string(block_size * 2, 'B');
            std::string cipher = oracle(input);

            std::vector<std::string> blocks;
            for (size_t j = 0; j < cipher.size(); j += block_size) {
                blocks.push_back(cipher.substr(j, block_size));
            }

            for (size_t j = 0; j < blocks.size() - 1; j++) {
                if (blocks[j] == blocks[j + 1]) {
                    pad_len = i;
                    block_id = j;
                    break;
                }
            }
            if (pad_len != -1) break;
        }

        std::cout << "Padding length: " << pad_len << ", Block ID: " << block_id << std::endl;

        // 逐字节解密
        std::string pad(pad_len, 'A');
        std::string answer;
        size_t total_len = oracle("").size();

        for (size_t byte_pos = 0; byte_pos < total_len; byte_pos++) {
            size_t short_len = block_size - 1 - (answer.size() % block_size);
            size_t current_block = block_id + (answer.size() / block_size);

            std::string target = oracle(pad + std::string(short_len, 'A'));
            target = target.substr(current_block * block_size, block_size);

            std::map<std::string, int> dict;
            for (int i = 0; i < 256; i++) {
                std::string test = pad + std::string(short_len, 'A') + answer + std::string(1, static_cast<char>(i));
                std::string enc = oracle(test);
                std::string block = enc.substr(current_block * block_size, block_size);
                dict[block] = i;
            }

            if (dict.find(target) != dict.end()) {
                answer += static_cast<char>(dict[target]);
            }
            else {
                break;
            }
        }

        // 输出结果
        size_t output_offset = block_id * block_size - pad_len;
        std::cout << "\nOffset: " << output_offset << std::endl;
        std::cout << "\nDecrypted text:\n" << pkcs7_unpad(answer) << std::endl;

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}