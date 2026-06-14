#include <iostream>
#include <string>

using namespace std;

// 扩展欧几里得算法
long long egcd(long long a, long long b, long long& x, long long& y)
{
    if (b == 0)
    {
        x = 1;
        y = 0;
        return a;
    }

    long long x1, y1;
    long long gcd = egcd(b, a % b, x1, y1);

    x = y1;
    y = x1 - (a / b) * y1;

    return gcd;
}

// 求模逆
long long invmod(long long a, long long m)
{
    long long x, y;
    long long gcd = egcd(a, m, x, y);

    if (gcd != 1)
    {
        cout << "模逆不存在！" << endl;
        exit(0);
    }

    return (x % m + m) % m;
}

// 快速模幂
long long modPow(long long base, long long exp, long long mod)
{
    long long result = 1;

    while (exp > 0)
    {
        if (exp % 2 == 1)
        {
            result = (result * base) % mod;
        }

        base = (base * base) % mod;
        exp /= 2;
    }

    return result;
}

int main()
{
    // 选取两个素数
    long long p = 17;
    long long q = 11;

    // 计算 n
    long long n = p * q;

    // 计算欧拉函数
    long long phi = (p - 1) * (q - 1);

    // 公钥指数
    long long e = 3;

    // 私钥指数
    long long d = invmod(e, phi);

    cout << "===== RSA密钥生成 =====" << endl;
    cout << "p = " << p << endl;
    cout << "q = " << q << endl;
    cout << "n = " << n << endl;
    cout << "phi(n) = " << phi << endl;
    cout << "e = " << e << endl;
    cout << "d = " << d << endl;

    cout << "\n公钥: (" << e << ", " << n << ")" << endl;
    cout << "私钥: (" << d << ", " << n << ")" << endl;

    // 测试数字42
    long long m = 42;

    cout << "\n原始消息 m = " << m << endl;

    // 加密
    long long c = modPow(m, e, n);

    cout << "加密后 c = " << c << endl;

    // 解密
    long long decrypted = modPow(c, d, n);

    cout << "解密后 m = " << decrypted << endl;

    return 0;
}