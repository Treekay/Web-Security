#ifndef _DES_H
#define _DES_H

#include <IOSTREAM>
#include <cstdlib>

using namespace std;

class DES {
private:
    uint64_t plainText; // 明文
    uint64_t cipherText; // 密文
    uint64_t key; // 用于生成子密钥的给定64位密钥 K
    uint64_t subkeys[16]; // 16个48位子密钥
    int mode; // 加密 or 解密
    uint64_t M; // 初始置换IP的结果
    uint64_t T; // 16轮迭代的结果
    uint64_t C; // IP-1逆置的结果
    uint32_t L, R; // M的前半部和后半部

    void initialPermutation();  // 初始IP置换
    void subkeyGeneration();    // 子密钥生成
    void feistelFunction(int);     // 轮函数
    void TIteration();   // 十六轮迭代T
    void inversePermutation();  // 逆置换
public:
    DES(uint64_t, uint64_t, int); // 构造函数
    uint64_t outputText(); // 输出64位
};

#endif // !_DES_H