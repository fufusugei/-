#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <cctype>

#pragma comment(lib, "bcrypt.lib")

// ==================== PKCS#7 填充 ====================
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
    if (pad_len == 0 || pad_len > data.size()) return data;
    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (static_cast<unsigned char>(data[i]) != pad_len) return data;
    }
    return data.substr(0, data.size() - pad_len);
}

// ==================== AES-CBC 使用 CNG ====================
std::vector<uint8_t> aes_cbc_crypt(
    const std::vector<uint8_t>& input,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    bool encrypt)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        nullptr,
        0
    );
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("OpenAlgorithmProvider failed");

    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("SetProperty failed");

    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        nullptr,
        0,
        (PUCHAR)key.data(),
        static_cast<ULONG>(key.size()),
        0
    );
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("GenerateSymmetricKey failed");

    std::vector<uint8_t> output(input.size());
    ULONG bytesDone = 0;

    status = encrypt ? BCryptEncrypt(
        hKey,
        (PUCHAR)input.data(),
        (ULONG)input.size(),
        nullptr,
        (PUCHAR)iv.data(),
        (ULONG)iv.size(),
        output.data(),
        (ULONG)output.size(),
        &bytesDone,
        0
    ) : BCryptDecrypt(
        hKey,
        (PUCHAR)input.data(),
        (ULONG)input.size(),
        nullptr,
        (PUCHAR)iv.data(),
        (ULONG)iv.size(),
        output.data(),
        (ULONG)output.size(),
        &bytesDone,
        0
    );
    if (!BCRYPT_SUCCESS(status)) throw std::runtime_error("Encrypt/Decrypt failed");

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return output;
}

// ==================== 辅助函数 ====================
std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); i++) result[i] = a[i] ^ b[i];
    return result;
}

std::string bytes_to_string(const std::vector<uint8_t>& v) {
    return std::string(v.begin(), v.end());
}

std::vector<uint8_t> string_to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ==================== CBC Bit Flipping Attack ====================
int main() {
    std::string key_str = "YELLOW SUBMARINE"; // 16 bytes
    std::vector<uint8_t> key(key_str.begin(), key_str.end());
    std::vector<uint8_t> iv(16, 0);

    std::string prefix = "comment1=cooking%20MCs;userdata=";
    std::string suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    auto filter = [](std::string s) -> std::string {
        size_t pos = 0;
        while ((pos = s.find(';', pos)) != std::string::npos) { s.replace(pos, 1, "%3B"); pos += 3; }
        pos = 0;
        while ((pos = s.find('=', pos)) != std::string::npos) { s.replace(pos, 1, "%3D"); pos += 3; }
        return s;
        };

    auto encrypt = [&](const std::string& userdata) -> std::vector<uint8_t> {
        std::string pt = pkcs7_pad(prefix + filter(userdata) + suffix);
        return aes_cbc_crypt(string_to_bytes(pt), key, iv, true);
        };

    auto decrypt = [&](const std::vector<uint8_t>& ciphertext) -> std::string {
        std::vector<uint8_t> pt = aes_cbc_crypt(ciphertext, key, iv, false);
        return pkcs7_unpad(bytes_to_string(pt));
        };

    // 计算填充，使目标块对齐
    size_t pad_len = (16 - (prefix.size() % 16)) % 16;
    std::string payload(pad_len + 16, 'A'); // 用于翻转

    std::vector<uint8_t> ct = encrypt(payload);

    // 计算目标块位置
    size_t block_id = (prefix.size() + pad_len) / 16;

    std::string target = ";admin=true;AAAA";

    // XOR 翻转前一块
    for (size_t i = 0; i < target.size(); i++) {
        ct[(block_id - 1) * 16 + i] ^= 'A' ^ target[i];
    }

    std::string pt = decrypt(ct);

    bool found = pt.find(";admin=true;") != std::string::npos;
    std::cout << std::boolalpha << found << "\n\n";

    // 输出可读明文
    std::cout << "Recovered Plaintext:\n";

    for (unsigned char c : pt)
    {
        if (c >= 32 && c <= 126)
        {
            std::cout << (char)c;
        }
        else
        {
            std::cout << '.';
        }
    }

    std::cout << "\n";

    auto pos = pt.find(";admin=true;");
    if (pos != std::string::npos) {
        std::cout << "Injected field:\n";
        std::cout << pt.substr(pos, 32) << "\n";
    }

    return 0;
}