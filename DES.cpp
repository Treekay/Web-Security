#include "DES.h"
#include "table.h"

/**
 * @msg: 构造函数
 */
DES::DES(uint64_t text, uint64_t k, int m) {
    plainText = text;
    key = k;
    mode = m;
    initialPermutation();  // 初始IP置换
    subkeyGeneration();    // 子密钥生成
    TIteration();   // 十六轮迭代
    inversePermutation(); // 逆置换
}

/**
 * @msg: 初始IP置换
 */
void DES::initialPermutation() {
    M = 0;
    for (int i = 0; i < 64; i++) {
        M <<= 1;
        M |= (plainText >> (64 - IP[i])) & 0x0000000000000001;
    }
}

/**
 * @msg: 生成子密钥
 */
void DES::subkeyGeneration() {
    /* 生成16个子密钥 */

    /* PC-1置换 */
    uint64_t C0D0 = 0; // 密钥K实行PC-1置换之后的结果
    for (int i = 0; i < 56; i++) {
        C0D0 <= 1;
        C0D0 |= (key >> (64 - PC1[i])) & 0x0000000000000001;
    }
    uint32_t C = (uint32_t)((C0D0 >> 28) & 0x000000000fffffff); // 前28位
    uint32_t D = (uint32_t)(C0D0 & 0x000000000fffffff); // 后28位

    /* 计算16个子密钥 */
    for (int i = 0; i < 16; i++) {

        /* LS置换 */
        for (int j = 0; j < LS[i]; j++) {
            C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);
            D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);
        }

        uint32_t CiDi = ((uint64_t)C << 28) | (uint64_t)D;

        /* PC-2压缩置换得到第i个子密钥 Ki */
        subkeys[i] = 0;
        for (int j = 0; j < 48; j++) {
            subkeys[i] <<= 1;
            subkeys[i] |= (CiDi >> (56 - PC2[j])) & 0x0000000000000001;
        }
    }
}

/**
 * @msg: 轮函数
 * @param {type} 
 * @return: 
 */
void DES::feistelFunction(int n) {
    uint64_t Ri = 0;
    /* E 扩展 */
    // 将32位的 R 扩展成48位的串 E
    for (int i = 0; i < 48; i++) {
        Ri <<= 1;
        Ri |= (uint64_t)((R >> (32 - E[i])) & 0x00000001);
    }

    // E与子密钥作48位二进制按位异或运算
    if (mode == 0) {
        // encryption
        Ri = Ri ^ subkeys[n];
    }
    else {
        // decryption
        Ri = Ri ^ subkeys[15 - n];
    }

    // 将E均分成八组与8个S盒进行6-4转换, 得到8个长度分别位4位的分组
    uint32_t F = 0;
    for (int i = 0; i < 8; i++) {
        char row = (char)((Ri & (0x0000840000000000 >> 6 * i)) >> 42 - 6 * i);
        row = (row >> 4) | row & 0x01;

        char column = (char)((Ri & (0x0000780000000000 >> 6 * i)) >> 43 - 6 * i);

        // 将分组结果顺序连接得到32位串
        F <<= 4;
        F |= (uint32_t)(S[i][16 * row + column] & 0x0f);
    }

    // P 置换得到结果
    uint32_t res = 0;
    for (int i = 0; i < 32; i++) {
        res <<= 1;
        res |= (F >> (32 - P[i])) & 0x0000000000000001;
    }

    // 交换L, R用于下一轮
    uint32_t temp = R;
    R = L ^ res;
    L = temp;
}

/**
 * @msg: 16轮迭代
 * @param {type} 
 * @return: 
 */
void DES::TIteration() {
    L = (uint32_t)((M >> 32) & 0x00000000ffffffff);
    R = (uint32_t)(M & 0x00000000ffffffff);
    for (int i = 0; i < 16; i++) {
        feistelFunction(i);
    }
    /* 交换置换 */
    // 左右交换 L16-R16 得到 R16-L16, 连接
    T = ((uint64_t)R << 32) | (uint64_t)L;
}



/**
 * @msg: 逆置换
 * @param {type} 
 * @return: 
 */
void DES::inversePermutation() {
    C = 0;
    for (int i = 0; i < 64; i++) {
        C << 1;
        C |= (T >> (64 - Inverse_IP[i])) & 0x0000000000000001;
    }
    cipherText = C;
}

/**
 * @msg: 输出64位
 * @param {type} 
 * @return: 
 */
uint64_t DES::outputText() {
    // 输出64位
    // cout << "Output text: ";
    // cout << cipherText << endl;
    return cipherText;
}