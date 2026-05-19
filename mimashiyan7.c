#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ================= SHA-1 实现 =================
typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    uint32_t buf_len;
} SHA1_CTX;

#define ROL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

void sha1_init(SHA1_CTX *ctx) {
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->len = 0;
    ctx->buf_len = 0;
}

void sha1_transform(SHA1_CTX *ctx, const uint8_t *data) {
    uint32_t w[80];
    for(int i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) | 
               ((uint32_t)data[i*4+2] << 8) | ((uint32_t)data[i*4+3]);
    for(int i = 16; i < 80; i++)
        w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];

    for(int i = 0; i < 80; i++) {
        uint32_t f, k;
        if(i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if(i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if(i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        uint32_t temp = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c;
    ctx->h[3] += d; ctx->h[4] += e;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->len += len * 8;
    while(len > 0) {
        size_t to_copy = 64 - ctx->buf_len;
        if(to_copy > len) to_copy = len;
        memcpy(ctx->buf + ctx->buf_len, data, to_copy);
        ctx->buf_len += to_copy;
        data += to_copy;
        len -= to_copy;

        if(ctx->buf_len == 64) {
            sha1_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void sha1_final(SHA1_CTX *ctx, uint8_t *hash) {
    ctx->buf[ctx->buf_len++] = 0x80;
    if(ctx->buf_len > 56) {
        while(ctx->buf_len < 64) ctx->buf[ctx->buf_len++] = 0x00;
        sha1_transform(ctx, ctx->buf);
        ctx->buf_len = 0;
    }
    while(ctx->buf_len < 56) ctx->buf[ctx->buf_len++] = 0x00;

    for(int i = 7; i >= 0; i--) 
        ctx->buf[ctx->buf_len++] = (ctx->len >> (i*8)) & 0xFF;
    sha1_transform(ctx, ctx->buf);

    for(int i = 0; i < 5; i++) {
        hash[i*4]   = (ctx->h[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
        hash[i*4+3] = ctx->h[i] & 0xFF;
    }
}

void compute_sha1(const char* input, char* out_hash) {
    SHA1_CTX ctx;
    uint8_t digest[20];
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)input, strlen(input));
    sha1_final(&ctx, digest);
    for(int i = 0; i < 20; i++) 
        sprintf(out_hash + i*2, "%02x", digest[i]);
    out_hash[40] = '\0';
}

// ================= 暴力破解 =================
const char target_hash[] = "67ae1a64661ac8b4494666f58c4822408dd0a3e4";

// 根据键盘指纹确定的8个物理按键的可能字符
// 每个物理按键对应一组可能的输出（普通按键 / Shift / 其他）
char key_options[8][4] = {
    {'(', '8'},           // 8 键: ( 或 8
    {'Q', 'q'},           // Q 键: Q 或 q
    {'=', '0'},           // 0 键: = 或 0
    {'W', 'w'},           // W 键: W 或 w
    {'I', 'i'},           // I 键: I 或 i
    {'N', 'n'},           // N 键: N 或 n
    {'*', '+'},           // * 键: * 或 +
    {'5', '5'}            // 5 键: 5（固定）
};

int opt_count[8] = {2, 2, 2, 2, 2, 2, 2, 1};

int found = 0;
long long checked = 0;

// 交换字符
void swap(char *a, char *b) {
    char temp = *a;
    *a = *b;
    *b = temp;
}

// 对固定的一组字符进行全排列
void permute(char *arr, int start, int end) {
    if (found) return;
    
    if (start == end) {
        char hash[41];
        compute_sha1(arr, hash);
        checked++;
        
        if (checked % 100000 == 0) {
            printf("\rChecked: %lld combinations... Current: %s", checked, arr);
            fflush(stdout);
        }
        
        if (strcmp(hash, target_hash) == 0) {
            found = 1;
            printf("\n\n========================================\n");
            printf("? Password found!\n");
            printf("========================================\n");
            printf("Password: %s\n", arr);
            printf("SHA1: %s\n", hash);
            printf("========================================\n");
        }
        return;
    }
    
    for (int i = start; i < end && !found; i++) {
        swap(&arr[start], &arr[i]);
        permute(arr, start + 1, end);
        swap(&arr[start], &arr[i]);
    }
}

int main() {
    printf("Target SHA1: %s\n", target_hash);
    printf("Searching for 8-character password...\n\n");
    
    // 遍历所有字符选择组合 (2^7 = 128 种)
    for (int mask = 0; mask < 128 && !found; mask++) {
        char chars[9];
        chars[0] = key_options[0][(mask >> 0) & 1];
        chars[1] = key_options[1][(mask >> 1) & 1];
        chars[2] = key_options[2][(mask >> 2) & 1];
        chars[3] = key_options[3][(mask >> 3) & 1];
        chars[4] = key_options[4][(mask >> 4) & 1];
        chars[5] = key_options[5][(mask >> 5) & 1];
        chars[6] = key_options[6][(mask >> 6) & 1];
        chars[7] = key_options[7][0];  // '5' 固定
        chars[8] = '\0';
        
        // 显示当前测试的字符集
        printf("\nTrying character set: %s\n", chars);
        permute(chars, 0, 8);
    }
    
    if (!found) {
        printf("\n\n? Password not found in all permutations\n");
    }
    
    printf("\nTotal combinations checked: %lld\n", checked);
    return 0;
}