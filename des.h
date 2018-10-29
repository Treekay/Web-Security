#ifndef _DES_H
#define _DES_H

#include <IOSTREAM>
#include <bitset>
#include <vector>
#include <string>

using namespace std;

class DES
{
  private:
    bitset<64> plainText;           // 输入
    bitset<64> cipherText;          // 输出
    bitset<64> key;                 // 用于生成子密钥的给定64位密钥 K
    bitset<48> subkeys[16];         // 16个48位子密钥
    int mode;                       // 加密 or 解密

    void subkeyGeneration(bitset<64>);                  // 子密钥生成
    bitset<64> initialPermutation(bitset<64>);          // 初始IP置换
    bitset<32> feistel(bitset<32>, bitset<48>);         // 轮函数
    bitset<64> TIteration(bitset<64>);                  // 十六轮迭代T
    bitset<64> inversePermutation(bitset<64>);          // 逆置换
  public:
    DES(string, string, int);                           // 构造函数
    void outputText();                                  // 输出64位
};

#endif // !_DES_H