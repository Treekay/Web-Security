#ifndef _DES_H
#define _DES_H

#include <IOSTREAM>
#include <cstdlib>
#include <cstdint>

using namespace std;

class DES {
private:
    uint64_t input; // 输入
    uint64_t output; // 输出
    uint64_t key; // 用于生成子密钥的给定64位密钥 K
    uint64_t subkeys[16]; // 16个48位子密钥
    int mode; // 加密 or 解密

    void subkeyGeneration(uint64_t);    // 子密钥生成
    uint64_t initialPermutation(uint64_t);  // 初始IP置换
    uint32_t feistelFunction(uint32_t, uint64_t);     // 轮函数
    uint64_t TIteration(uint64_t);   // 十六轮迭代T
    uint64_t inversePermutation(uint64_t);  // 逆置换
public:
    DES(uint64_t, uint64_t, int); // 构造函数
    uint64_t outputText(); // 输出64位
};

#endif // !_DES_H