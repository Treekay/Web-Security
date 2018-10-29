#include "des.h"

int main()
{
    // 输入内容和密钥
    string str, key;
    cout << "Input: ";
    cin >> str;
    cout << "Key: ";
    cin >> key;

    // 选择加密或解密
    int mode;
    cout << "Select mode: 0 Encrypt / 1 Decrypt" << endl;
    cin >> mode;

    DES des(str, key, mode);

    return 0;
}