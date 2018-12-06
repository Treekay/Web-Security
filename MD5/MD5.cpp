#include "MD5.hpp"

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))
#define CLS(x, n) ((x << n) | (x >> (32 - n)))

MD5::MD5(string s) {
    input = s;
    padding();
    process();
}

void MD5::padding() {
    uint64_t K = input.length() * 8; // 总 bits 数
    uint64_t P = (K % 512 == 448) ? 512 : (488 - K % 512); // 要补的 bits

    /* 用来存储的 N 个 32 bits 字*/
    blockNum = (K + P + 64)/ 512; // 预留 64 位来存储原 bits 长度
    paddingWord = new uint32_t[blockNum * 16]; // 每块16个字, 即 16 * 4 * 8 = 512 bits
    memset(paddingWord, 0, blockNum * 16); // 初始化为0

    /* 将原字符序列按顺序用字存储, 字节为小端存储 */
    memcpy(paddingWord, input.c_str(), input.length());

    /* 补位 100....0 */
    int lastCharIndex = input.length() / 4; // 最后一个字节所在的字的位置
    int addIndex = (input.length() % 4) * 8; // 尾部余下的不足一个字的字节
    paddingWord[lastCharIndex] |= (0x80 << addIndex); // 小端存储, 在最低字节的补位数据在最左边, 需要左移

    /* 最后 64 位存储 K 的低64位 */
    int lengthIndex = blockNum * 16 - 2; // 最后的 64 位
    paddingWord[lengthIndex] = K; // 用来保存长度数值
}

void MD5::process(){
    uint32_t CV[4] = {A, B, C, D};   // 初始化 IV
    for (int i = 0; i < blockNum; i++) {    // 对每个 512 bits 的块作 4 轮循环压缩
        uint32_t block[16];         // 每 16 个字为一个块 
        memcpy(block, paddingWord + i * 16, 64);
        compress(CV, block);
    }
    CV2MD(CV);
}

void MD5::compress(uint32_t CV[4], uint32_t block[16]) {
    uint32_t g, k;
    uint32_t a = CV[0], b = CV[1], c = CV[2], d = CV[3];
    for (int i = 0; i < 64; i++) {
        // 轮函数
        if (i < 16) {
            g = F(b, c, d);
            k = i;
        }
        else if (i < 32) {
            g = G(b, c, d);
            k = (5 * i + 1) % 16;
        }
        else if (i < 48) {
            g = H(b, c, d);
            k = (3 * i + 5) % 16;
        }
        else {
            g = I(b, c, d);
            k = (7 * i) % 16;
        }
        // g 是对 b, c, d 块用轮函数, CLS 是将32位循环左移 s 位
        // 对 A 进行迭代
        uint32_t temp = b + CLS((a + g + block[k] + T[i]), s[i]);
        // 循环轮替
        a = d;
        d = c;
        c = b;
        b = temp;
    }
    // 结果用作下一轮输入的 CV
    CV[0] = a + CV[0];
    CV[1] = b + CV[1];
    CV[2] = c + CV[2];
    CV[3] = d + CV[3];
}

void MD5::CV2MD(uint32_t CV[4]) {
    unsigned char md[16];
    memcpy(md, CV, 16);         // 将字拆分成字节
    for (int i = 0; i < 16; i++) {
        printf("%02x", md[i]);
    }
    cout << endl;
}