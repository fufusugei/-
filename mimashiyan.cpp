#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <cstdint>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

using namespace CryptoPP;

// 1. 恢复 MRZ 中缺失的数字
char recover_mrz_character(const std::string& mrz_partial)
{
    const int weights[3] = { 7, 3, 1 };

    // 构造 char -> value 映射
    auto char_to_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'Z') return 10 + (c - 'A');
        if (c == '<') return 0;
        throw std::invalid_argument("invalid MRZ character");
        };

    auto checksum = [&](const std::string& text) -> int {
        int sum = 0;
        for (size_t i = 0; i < text.size(); ++i) {
            sum += char_to_val(text[i]) * weights[i % 3];
        }
        return sum % 10;
        };

    // 找出第一个 '?' 的位置（代码里只替换一次）
    size_t qpos = mrz_partial.find('?');
    if (qpos == std::string::npos) {
        throw std::invalid_argument("no '?' in MRZ");
    }

    // 提取用于校验的子串 21:27 和校验位 27
    // 注意：原 Python 代码中字符串索引从 0 开始，且该 MRZ 长度固定
    if (mrz_partial.size() < 28) {
        throw std::invalid_argument("MRZ too short");
    }

    std::string candidate = mrz_partial;
    for (char digit = '0'; digit <= '9'; ++digit) {
        candidate[qpos] = digit;
        // 取索引 [21,27) -> 6位, 索引 27 是校验位
        std::string check_part = candidate.substr(21, 6);
        int check_digit = candidate[27] - '0';
        if (checksum(check_part) == check_digit) {
            return digit;
        }
    }
    throw std::runtime_error("missing MRZ character not found");
}

// 2. 设置奇偶校验位
byte set_odd_parity(byte b)
{
    byte masked = b & 0xFE;
    int bits_count = 0;
    byte tmp = masked;
    while (tmp) {
        bits_count += (tmp & 1);
        tmp >>= 1;
    }
    // 如果已有奇数个 1，末尾设 0；否则设 1
    return masked | (bits_count % 2 == 1 ? 0 : 1);
}

// 3. AES-CBC 解密
std::string aes_cbc_decrypt(const std::string& ciphertext, const SecByteBlock& key, const SecByteBlock& iv)
{
    std::string plaintext;
    try {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        StringSource ss(ciphertext, true,
            new StreamTransformationFilter(dec,
                new StringSink(plaintext)
            )
        );
    }
    catch (const Exception& e) {
        std::cerr << "Crypto++ AES decrypt error: " << e.what() << std::endl;
        throw;
    }
    return plaintext;
}

// 4. 去除 BAC padding (类似 PKCS#7 但略有不同)
std::string strip_bac_padding(const std::string& data)
{
    // 去除末尾连续的 '\x00'
    size_t end = data.size();
    while (end > 0 && data[end - 1] == '\x00') {
        --end;
    }
    if (end > 0 && data[end - 1] == '\x01') {
        // 去掉这个 0x01
        return data.substr(0, end - 1);
    }
    return data.substr(0, end);
}

// 辅助 Base64 解码
std::string base64_decode(const std::string& encoded)
{
    std::string decoded;
    StringSource ss(encoded, true,
        new Base64Decoder(
            new StringSink(decoded)
        )
    );
    return decoded;
}

int main()
{
    try {
        // 原始数据
        std::string mrz_partial = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4";

        // 恢复缺失的数字
        char recovered = recover_mrz_character(mrz_partial);
        std::cout << "Recovered digit: " << recovered << std::endl;

        // 补全 MRZ
        std::string mrz_full = mrz_partial;
        size_t qpos = mrz_full.find('?');
        if (qpos != std::string::npos) {
            mrz_full[qpos] = recovered;
        }

        // 提取 mrz_info: [0:10] + [13:20] + [21:28]
        std::string mrz_info = mrz_full.substr(0, 10)
            + mrz_full.substr(13, 7)
            + mrz_full.substr(21, 7);
        std::cout << "MRZ info: " << mrz_info << std::endl;

        // 计算 K_seed (SHA1 前 16 字节)
        SHA1 sha1;
        SecByteBlock digest_sha1(SHA1::DIGESTSIZE);
        sha1.CalculateDigest(digest_sha1, (const byte*)mrz_info.data(), mrz_info.size());

        SecByteBlock k_seed(16);
        std::copy(digest_sha1.begin(), digest_sha1.begin() + 16, k_seed.begin());

        // 计算 raw_key: SHA1(k_seed || 0x00000001)
        SecByteBlock raw_key_hash(SHA1::DIGESTSIZE);
        SHA1 sha1_2;
        sha1_2.Update(k_seed, k_seed.size());
        uint32_t counter = 1;
        byte counter_bytes[4] = {
            (byte)((counter >> 24) & 0xFF),
            (byte)((counter >> 16) & 0xFF),
            (byte)((counter >> 8) & 0xFF),
            (byte)(counter & 0xFF)
        };
        sha1_2.Update(counter_bytes, 4);
        sha1_2.Final(raw_key_hash);

        SecByteBlock raw_key(16);
        std::copy(raw_key_hash.begin(), raw_key_hash.begin() + 16, raw_key.begin());

        // 对 raw_key 每个字节设置奇偶校验位
        SecByteBlock key_enc(16);
        for (size_t i = 0; i < 16; ++i) {
            key_enc[i] = set_odd_parity(raw_key[i]);
        }

        std::cout << "Key (hex): ";
        for (byte b : key_enc) {
            printf("%02x", b);
        }
        std::cout << std::endl;

        // 密文 (Base64)
        std::string b64_cipher = "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jx"
            "aa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2N"
            "fNnWFBTXyf7SDI";
        std::string ciphertext = base64_decode(b64_cipher);

        // AES-CBC 解密，IV 全 0
        SecByteBlock iv(16, 0x00);
        std::string plaintext_padded = aes_cbc_decrypt(ciphertext, key_enc, iv);

        // 去除特殊填充
        std::string plaintext = strip_bac_padding(plaintext_padded);

        std::cout << "Decrypted text: " << plaintext << std::endl;

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}