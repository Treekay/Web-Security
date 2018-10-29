#include "DES.h"
#include "table.h"

/**
 * @msg: 构造函数
 * @param t: 输入的内容
 * @parma k: 密钥
 * @param m: 选择的模式 （0 加密 / 1 解密）
 */
DES::DES(bitset<64> s, bitset<64> k, int m) {
    mode = m;
    // if (mode == 0)
    //     cout << "Encrypt: " << s << " -> ";
    // else
    //     cout << "Dectypt: " << s << " -> ";

    plainText = s;
    key = k;

    // 子密钥生成
    subkeyGeneration(key);

    // DES加密过程, 对64位块加密
    bitset<64> M = plainText;
    bitset<64> M0 = initialPermutation(M);   // 初始IP置换
    bitset<64> RL = TIteration(M0);          // 十六轮迭代
    bitset<64> C = inversePermutation(RL);    // 逆置换
    cipherText = C;
    outputText();
}

/**
 * @msg: 初始IP置换
 * @param t: 当前正在处理的明文块
 */
bitset<64> DES::initialPermutation(bitset<64> M) {
    // 初始IP置换
    bitset<64> M0;
    for (int i = 0; i < 64; i++) {
        M0[63-i] = M[64-IP[i]]; // 置换表是从1开始, 而bitset下标是从0开始
    }
    return M0;
}

/**
 * @msg: 生成子密钥
 * @param key: 密钥
 */
void DES::subkeyGeneration(bitset<64> key) {
    /* 生成16个子密钥 */

    /* PC-1置换 */
    bitset<56> realKey;
    for (int i = 0; i < 56; i++) {
        realKey[55-i] = key[64 - PC1[i]]; // 置换表是从1开始, 而bitset下标是从0开始
    }
    
    // 16轮生成16个子密钥
    for (int i = 0; i < 16; i++) {
        bitset<28> C; // 前28位
        bitset<28> D; // 后28位
        for (int i = 28; i < 56; i++) {
            C[i - 28] = realKey[i];
        }
        for (int i = 0; i < 28; i++) {
            D[i] = realKey[i];
        }

        /* LS置换 */
        int shift = LS[i];
        bitset<28> tempC = C;
        bitset<28> tempD = D;
        for (int j = 27; j >= 0; j--) {
            C[j] = tempC[(j + 28 - shift) % 28];
            D[j] = tempD[(j + 28 - shift) % 28];
        }
        // 将左右两部分重新组合成56位
        bitset<56> LR;
        for (int j = 28; j < 56; j++) {
            LR[j] = C[j - 28];
        }
        for (int j = 0; j < 28; j++) {
            LR[j] = D[j];
        }
        /* PC-2 压缩置换 */
        for (int j = 0; j < 48; j++) {
            subkeys[i][47 - j] = LR[56 - PC2[j]];
        }
    }
}

/**
 * @msg: 轮函数
 * @param {type} 
 * @return: 
 */
bitset<32> DES::feistel(bitset<32> R, bitset<48> Ki) {
    /* E 扩展 */
    bitset<48> resE; // 将32位的串R作E-扩展之后的结果
    for (int i = 0; i < 48; i++) {
        resE[47 - i] = R[32 - E[i]];
    }
    // resE与子密钥作48位二进制按位异或运算
    resE = resE ^ Ki;
    // 将E均分成八组
    // 与8个S盒进行6-4转换, 得到8个长度分别位4位的分组
    // 将分组结果按顺序连接得到32位的串
    bitset<32> resS;
    for (int i = 0, x = 0; i < 48; i += 6, x += 4) {
        int row = resE[47 - i] * 2 + resE[47 - i - 5];
        int col = resE[47 - i - 1] * 8 + resE[47 - i - 2] * 4 + resE[47 - i - 3] * 2 + resE[47 - i - 4];
        int num = S[i / 6][row][col];
        bitset<4> binary(num);
        resS[31 - x] = binary[3];
        resS[31 - x - 1] = binary[2];
        resS[31 - x - 2] = binary[1];
        resS[31 - x - 3] = binary[0];
        x += 4;
    }
    // P 置换得到结果
    bitset<32> resP;
    for (int i = 0; i < 32; i++) {
        resP[31 - i] = resS[32 - P[i]];
    }
    return resP;
}

/**
 * @msg: 16轮迭代
 * @param {type} 
 * @return: 
 */
bitset<64> DES::TIteration(bitset<64> M0) {
    bitset<32> L; // 前32位
    bitset<32> R; // 后32位
    for (int i = 32; i < 64; i++) {
        L[i - 32] = M0[i];
    }
    for (int i = 0; i < 32; i++) {
        R[i] = M0[i];
    }
    /* 16 次迭代 */
    bitset<32> nextL;
    for (int i = 0; i < 16; i++) {
        nextL = R;
        bitset<32> f;
        if (mode == 0)
            f = feistel(R, subkeys[i]);
        else 
            f = feistel(R, subkeys[15 - i]);
        R = L ^ f;
        L = nextL;
    }
    /* W 置换 */
    // 左右交换 L16-R16 得到 R16-L16, 连接
    bitset<64> RL;
    for (int i = 0; i < 32; i++) {
        RL[i] = L[i];
    }
    for (int i = 32; i < 64; i++) {
        RL[i] = R[i - 32];
    }
    return RL;
}

/**
 * @msg: 逆置换
 * @param {type} 
 * @return: 
 */
bitset<64> DES::inversePermutation(bitset<64> RL) {
    bitset<64> C;
    for (int i = 0; i < 64; i++) {
        C[63 - i] = RL[64 - Inverse_IP[i]];
    }
    return C;
}

/**
 * @msg: 输出64位
 * @param {type} 
 * @return: 
 */
bitset<64> DES::outputText() {
    // 输出64位
    return cipherText;
}