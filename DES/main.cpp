#include "DES.cpp"

int main() {
    int mode; 
    string key, input, data, filePath = "cipher";

    /* 选择加密或解密 */
    cout << "mode: "; 
    cin >> mode;

    /* 输入密钥 */
    cout << "key: "; 
    cin >> key;

    /* 输入内容 */
    if (mode == 0) {
        cout << "input: ";
        cin >> input;
    }
    else if (mode == 1) {
        input = readFileToString(filePath); 
    }

    /* DES过程 */
    vector<bitset<64>> blocks = PKCS_IN(input, mode);
    for (int i = 0; i < blocks.size(); i++) {
        DES des(blocks[i], charsToBitset(key.c_str()), mode);
        writeFileToString(des.outputText(), filePath, mode);
    }
    PKCS_OUT(filePath, mode);

    return 0;
}