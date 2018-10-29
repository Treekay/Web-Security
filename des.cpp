#include "des.h"
#include "table.h"

/**
 * @msg: 构造函数
 * @param t: 输入的内容
 * @parma k: 密钥
 * @param m: 选择的模式 （0 加密 / 1 解密）
 */
DES::DES(string s, string k, int m) {
    mode = m;
    if (mode == 0)
        cout << "Encrypt: " << s << " -> ";
    else
        cout << "Dectypt: " << s << " -> ";

    // 将输入的内容和密钥转位64位的分组
    plainText = ECB(s);
    key = ECB(k)[0];
    // 子密钥生成
    subkeyGeneration(key);
    // DES加密过程, 对每个64位块单独加密
    for (int t = 0; t < plainText.size(); t++) {
        // 初始IP置换
        bitset<64> M = plainText[t];
        bitset<64> M0 = initialPermutation(M);   // 初始IP置换
        bitset<64> RL = TIteration(M0);          // 十六轮迭代
        bitset<64> C = inversePermutation(RL);    // 逆置换
        outputText(C);
    }
}

/**
 * @msg: 将输入的内容和密钥转为64位的分组
 * @param str: 输入的内容和密钥
 */
vector<bitset<64>> DES::ECB(string str) {
    // 将输入内容转化为64位分组
    int len = str.length();
    int pktNum = len / 8 + 1;
    int addNum = 8 - len % 8;
    // 拼接补齐到64位的分组
    for (int t = 0; t < addNum; t++) {
        str += to_string(addNum);
    }
    vector<bitset<64>> temp;
    // 将每8个字节转为64位
    for (int t = 0; t < pktNum; t++) {
        bitset<64> bits;
        const char *s = (str.substr(t * 8, (t + 1) * 8 - 1)).c_str();
        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                bits[i * 8 + j] = ((s[i] >> j) & 1);
            }
        }
        temp.push_back(bits);
    }
    return temp;
}

/**
 * @msg: 初始IP置换
 * @param t: 用于标记当前正在处理的明文块
 */
bitset<64> DES::initialPermutation(bitset<64> M) {
    // 初始IP置换
    bitset<64> M0;
    for (int i = 0; i < 64; i++) {
        M0[i] = M[IP[i]-1]; // 置换表是从1开始, 而bitset下标是从0开始
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
        realKey[i] = key[PC1[i] - 1]; // 置换表是从1开始, 而bitset下标是从0开始
    }
    bitset<28> C; // 前28位
    bitset<28> D; // 后28位
    for (int i = 0; i < 28; i++) {
        C[i] = realKey[i];
        D[i] = realKey[i + 28];
    }
    // 16轮生成16个子密钥
    for (int i = 0; i < 16; i++) {
        /* LS置换 */
        int pos = LS[i];
        bitset<28> tempC = C;
        bitset<28> tempD = D;
        for (int j = 0; j < 28; j++) {
            C[j] = tempC[(j + 28 - pos) % 28];
            D[j] = tempD[(j + 28 - pos) % 28];
        }
        // 将左右两部分重新组合成56位
        bitset<56> LR;
        for (int j = 0; j < 28; j++) {
            LR[j] = C[j];
            LR[j + 28] = D[j];
        }
        /* PC-2 压缩置换 */
        for (int j = 0; j < 48; j++) {
            subkeys[i][j] = LR[PC2[j] - 1];
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
        resE[i] = R[E[i] - 1];
    }
    // resE与子密钥作48位二进制按位异或运算
    for (int i = 0; i < 48; i++) {
        resE[i] = resE[i] ^ Ki[i];
    }
    // 将E均分成八组
    bitset<6> Ei[8]; 
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 6; j++) {
            Ei[i][j] = resE[i * 8 + j];
        }
    }
    // 与8个S盒进行6-4转换, 得到8个长度分别位4位的分组
    bitset<4> Si[8];
    for (int i = 0; i < 8; i++) {
        // 根据输入的6位确定行号列号
        bitset<2> rowBit;
        bitset<4> colBit;
        rowBit[0] = Ei[i][0];
        rowBit[1] = Ei[i][5];
        colBit[0] = Ei[i][1];
        colBit[1] = Ei[i][2];
        colBit[2] = Ei[i][3];
        colBit[3] = Ei[i][4];
        int row = rowBit.to_ulong() - 1;
        int col = colBit.to_ulong() - 1;
        char val = S[16 * row + col][0];
        for (int j = 0; j < 4; ++j) {
            Si[i][j] = ((val >> j) & 1);
        }
    }
    // 将分组结果按顺序连接得到32位的串
    bitset<32> resS;
    for (int i = 0; i <8; i++) {
        resS[i * 4] = Si[i][0];
        resS[i * 4 + 1] = Si[i][1];
        resS[i * 4 + 2] = Si[i][2];
        resS[i * 4 + 3] = Si[i][3];
    }
    // P 置换得到结果
    bitset<32> resP;
    for (int i = 0; i < 32; i++) {
        resP[i] = resS[P[i] - 1];
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
    for (int i = 0; i < 32; i++) {
        L[i] = M0[i];
        R[i] = M0[i + 32];
    }
    /* 16 次迭代 */
    bitset<32> lastR, lastL, nextR, nextL;
    lastR = R;
    lastL = L;
    for (int i = 0; i < 16; i++) {
        nextL = lastR;
        bitset<32> f;
        if (mode == 0)
            f = feistel(lastR, subkeys[i]);
        else 
            f = feistel(lastR, subkeys[15 - i]);
        for (int j = 0; j < 32; j++) {
            nextR[j] = lastL[j] ^ f[j];
        }
        // 交换L, R用于下一轮
        lastL = nextL;
        lastR = nextR;
    }
    L = lastL;
    R = lastR;
    /* W 置换 */
    // 左右交换 L16-R16 得到 R16-L16, 连接
    bitset<64> RL;
    for (int i = 0; i < 32; i++) {
        RL[i] = R[i];
        RL[i + 32] = L[i];
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
        C[i] = RL[Inverse_IP[i] - 1];
    }
    return C;
}

/**
 * @msg: 输出64位
 * @param {type} 
 * @return: 
 */
void DES::outputText(bitset<64> C) {
    // 输出64位
    cout << C.to_ullong() << endl;
}