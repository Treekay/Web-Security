#include "DES.cpp"

int main() {
    int mode; 
    fstream file;
    string input, key, output, inputPath, outputPath;

    // 选择加密或解密
    cout << "mode: ";
    cin >> mode;
    if (mode == 0) {
        inputPath = "plain";
        outputPath = "cipher";
    } else {
        inputPath = "cipher";
        outputPath = "plain";
    }
    // 输入密钥
    cout << "key: ";
    cin >> key;
    input = readFileToString(inputPath); // 读取内容

    /* 构建64位块 */
    vector<bitset<64>> blocks = PKCS_IN(input, mode);
    // 分多次将每个64位块分别加密
    for (size_t i = 0; i < blocks.size(); i++) {
        // DES 过程
        DES des(blocks[i], charsToBitset(key.c_str()), mode);
        bitset<64> cipher = des.outputText();
        // 写入文件
        file.open(outputPath.c_str(), ios::binary | ios::app);
        file.write((char *)&cipher, sizeof(cipher));
        file.close();
    }
    // 最后一块包含补全位数, 需要特殊处理
    PKCS_OUT(outputPath, mode);

    // 删除输入文件
    if (mode == 0) {
        remove("plain");
    }
    else {
        remove("cipher");
    }

    return 0;
}