#include <iostream>

using namespace std;

// 欧几里得算法求最大公约数
long long myGCD(long long a, long long b)
{
    while (b != 0)
    {
        long long temp = a % b;
        a = b;
        b = temp;
    }
    return a;
}

int main()
{
    long long p = 1009;
    long long q = 3643;

    long long phi = (p - 1) * (q - 1);

    long long minFixed = 999999999999LL;
    long long sumE = 0;

    for (long long e = 2; e < phi; e++)
    {
        // e与phi互质
        if (myGCD(e, phi) != 1)
            continue;

        // 未加密信息数量
        long long fixedCount =
            (1 + myGCD(e - 1, p - 1)) *
            (1 + myGCD(e - 1, q - 1));

        if (fixedCount < minFixed)
        {
            minFixed = fixedCount;
            sumE = e;
        }
        else if (fixedCount == minFixed)
        {
            sumE += e;
        }
    }

    cout << "最少未加密信息数: " << minFixed << endl;
    cout << "满足条件的e之和: " << sumE << endl;

    return 0;
}