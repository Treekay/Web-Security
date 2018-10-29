#include "DES.h"
#include "table.h"

/**
 * @msg: 构造函数
 * @param t: 输入的内容
 * @parma k: 密钥
 * @param m: 选择的模式 （0 加密 / 1 解密）
 */
DES::DES(uint64_t text, uint64_t k, int m) {
    input = text;
    key = k;
    mode = m;
    if (mode == 0)
        cout << "Encrypt: " << text << " -> ";
    else
        cout << "Dectypt: " << text << " -> ";

    subkeyGeneration(key);    // 子密钥生成
    
    uint64_t M = input;
    uint64_t M0 = initialPermutation(M); // 初始IP置换
    uint64_t RL = TIteration(M0);         // 十六轮迭代
    uint64_t C = inversePermutation(RL);  // 逆置换
    outputText();
}

/**
 * @msg: 初始IP置换
 * @param M: 初始明文块
 */
uint64_t DES::initialPermutation(uint64_t M) {
    // 初始IP置换
    uint64_t M0 = 0;
    for (int i = 0; i < 64; i++) {
        M0 <<= 1;
        M0 |= (input >> (64 - IP[i])) & 0x0000000000000001;
    }
    return M0;
}

/**
 * @msg: 生成子密钥
 * @param key: 密钥
 */
void DES::subkeyGeneration(uint64_t key) {
    /* 生成16个子密钥 */

    /* PC-1置换 */
    uint64_t realKey = 0; // 密钥K实行PC-1置换之后的结果
    for (int i = 0; i < 56; i++) {
        realKey <= 1;
        realKey |= (key >> (64 - PC1[i])) & 0x0000000000000001;
    }
    uint32_t C = (uint32_t)((realKey >> 28) & 0x000000000fffffff); // 前28位
    uint32_t D = (uint32_t)(realKey & 0x000000000fffffff); // 后28位

    /* 生成16个子密钥 */
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
uint32_t DES::feistelFunction(uint32_t R, uint64_t subkey) {
    /* E 扩展 */
    // 将32位的 R 扩展成48位的串 E
    uint64_t resE = 0;
    for (int i = 0; i < 48; i++) {
        resE <<= 1;
        resE |= (uint64_t)((R >> (32 - E[i])) & 0x00000001);
    }

    // E与子密钥作48位二进制按位异或运算
    resE = resE ^ subkey;

    // 将E均分成八组与8个S盒进行6-4转换, 得到8个长度分别位4位的分组
    uint32_t resS = 0;
    for (int i = 0; i < 8; i++) {
        char row = (char)((resE & (0x0000840000000000 >> 6 * i)) >> 42 - 6 * i);
        row = (row >> 4) | row & 0x01;
        char column = (char)((R & (0x0000780000000000 >> 6 * i)) >> 43 - 6 * i);

        // 将分组结果顺序连接得到32位串
        resS <<= 4;
        resS |= (uint32_t)(S[i][16 * row + column] & 0x0f);
    }

    // P 置换得到结果
    uint32_t resP = 0;
    for (int i = 0; i < 32; i++) {
        resP <<= 1;
        resP |= (resS >> (32 - P[i])) & 0x0000000000000001;
    }

    return resP;
}

/**
 * @msg: 16轮迭代
 * @param {type} 
 * @return: 
 */
uint64_t DES::TIteration(uint64_t M0) {
    uint32_t L = (uint32_t)((M0 >> 32) & 0x00000000ffffffff);
    uint32_t R = (uint32_t)(M0 & 0x00000000ffffffff);
    for (int i = 0; i < 16; i++) {
        uint32_t subkey, temp;
        if (mode == 0) // encryption
            subkey = subkeys[i];
        else // decryption
            subkey = subkeys[15 - i];
        
        temp = R;
        R = L ^ feistelFunction(R, subkey);
        L = temp;
    }
    /* W 置换 */
    // 左右交换 L16-R16 得到 R16-L16, 连接
    uint64_t RL = ((uint64_t)R << 32) | (uint64_t)L;
    return RL;
}



/**
 * @msg: 逆置换
 * @param {type} 
 * @return: 
 */
uint64_t DES::inversePermutation(uint64_t RL) {
    uint64_t C = 0;
    for (int i = 0; i < 64; i++) {
        C <<= 1;
        C |= (RL >> (64 - Inverse_IP[i])) & 0x0000000000000001;
    }
    output = C;
    return C;
}

/**
 * @msg: 输出64位
 * @param {type} 
 * @return: 
 */
uint64_t DES::outputText() {
    // 输出64位
    cout << output << endl;
}