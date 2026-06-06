#include <iostream>
#include <string>
#include <algorithm>
#include <random>
#include <openssl/evp.h>

// PKCS#7 填充
std::string pkcs7_pad(const std::string& data, size_t block_size = 16) {
    size_t pad_len = block_size - (data.size() % block_size);
    if (pad_len == 0) pad_len = block_size;
    std::string padded = data;
    padded.append(pad_len, static_cast<char>(pad_len));
    return padded;
}

// PKCS#7 去填充
std::string pkcs7_unpad(const std::string& data) {
    if (data.empty()) return "";
    size_t pad_len = static_cast<unsigned char>(data.back());
    return data.substr(0, data.size() - pad_len);
}

// AES-ECB 加解密
std::string aes_ecb(const std::string& data, const std::string& key, bool encrypt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
        (const unsigned char*)key.c_str(), nullptr, encrypt);

    std::string result(data.size() + 16, '\0');
    int len = 0, total_len = 0;
    EVP_CipherUpdate(ctx, (unsigned char*)&result[0], &len,
        (const unsigned char*)data.c_str(), data.size());
    total_len = len;
    EVP_CipherFinal_ex(ctx, (unsigned char*)&result[total_len], &len);
    total_len += len;
    EVP_CIPHER_CTX_free(ctx);

    result.resize(total_len);
    return result;
}

// Profile 函数
std::string profile_for(const std::string& email) {
    std::string clean = email;
    clean.erase(std::remove(clean.begin(), clean.end(), '&'), clean.end());
    clean.erase(std::remove(clean.begin(), clean.end(), '='), clean.end());
    return "email=" + clean + "&uid=10&role=user";
}

int main() {
    // 生成随机密钥
    std::mt19937 rng(20260515);
    std::string key(16, '\0');
    for (int i = 0; i < 16; i++)
        key[i] = rng() % 256;

    // 攻击：构造 admin 块
    std::string admin_block = aes_ecb(pkcs7_pad(profile_for(std::string(10, 'A') + "admin" + std::string(11, 11))), key, true).substr(16, 16);

    // 构造伪造的密文
    std::string forged = aes_ecb(pkcs7_pad(profile_for(std::string(13, 'A'))), key, true).substr(0, 32) + admin_block;

    // 解密并输出
    std::cout << pkcs7_unpad(aes_ecb(forged, key, false)) << std::endl;

    return 0;
}