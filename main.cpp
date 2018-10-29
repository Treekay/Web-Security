#include "des.cpp"

int main()
{
    // 选择加密或解密
    int mode; // 0 Encrypt / 1 Decrypt
    cout << "Mode: ";
    cin >> mode;

    // 输入内容和密钥
    string str, key;
    cout << "Input: ";
    cin >> str;
    cout << "Key: ";
    cin >> key;

    DES des(str, key, mode);

    return 0;
}