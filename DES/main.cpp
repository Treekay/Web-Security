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
    input = readFileToString(inputPath.c_str()); // 读取内容

    /* 构建64位块 */
    vector<bitset<64>> blocks = ECB(input);
    // 分多次将每个64位块分别加密
    for (int i = 0; i < blocks.size(); i++) {
        // 解密 or 加密
        DES des(blocks[i], charsToBitset(key.c_str()), mode);
        bitset<64> cipher = des.outputText();
        // 将结果写入文件
        file.open(outputPath.c_str(), ios::binary | ios::app);
        file.write((char *)&cipher, sizeof(cipher));
        file.close();
    }
    // 删除输入文件
    if (mode == 0) {
        remove("plain");
    }
    else {
        remove("cipher");
    }
    
    // 输出结果
    // output = readFileToString(outputPath.c_str());
    // cout << "key: " << key << endl;
    // cout << "input: " << input << endl;
    // cout << "output: " << output << endl;

    return 0;
}