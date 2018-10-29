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
    vector<bitset<64>> plainText;       // 输入
    vector<bitset<64>> cipherText;      // 输出
    bitset<64> key;         // 用于生成子密钥的给定64位密钥 K
    bitset<48> subkeys[16]; // 16个48位子密钥
    int mode;             // 加密 or 解密
    bitset<64> M;           // 初始置换IP的结果
    bitset<64> T;           // 16轮迭代的结果
    bitset<64> C;           // IP-1逆置的结果
    bitset<32> L, R;        // M的前半部和后半部

    void processInput(string, string);    // 将输入的内容和密钥转为64位的分组
    vector<bitset<64>> ECB(const char *, const char *); // 将输入的内容和密钥转为64位的分组
    void charToBitset(const char * s); // 将8个字符转为64位
    void initialPermutation(); // 初始IP置换
    void subkeyGeneration();   // 子密钥生成
    void feistelFunction(int); // 轮函数
    void TIteration();         // 十六轮迭代T
    void inversePermutation(); // 逆置换
  public:
    DES(string, string, int); // 构造函数
    bitset<64> outputText();        // 输出64位
};

#endif // !_DES_H