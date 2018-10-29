#include "DES.cpp"

using namespace std;

int main(void) {
    uint64_t text;
    uint64_t key;
    int mode;

    // 输入
    cout << "Input: ";
    cin >> text;
    cout << "Key: ";
    cin >> key;
    // 0 加密, 1解密
    cout << "Mode: ";
    cin >> mode;
    
    // 测试
    DES testEncrypt(text, key, mode);
    uint64_t output = testEncrypt.outputText();
    if (mode == 0)
        cout << "Encryption: " << output << endl;
    else 
        cout << "Decryption: " << output << endl;
    return 0;
}