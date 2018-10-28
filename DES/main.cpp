#include <string>
#include <sstream>

#include "DES.cpp"

using namespace std;

int main(void) {
    // 测试加密

    // 输入字符串
    string str, k;
    cout << "Input text: ";
    cin >> str;
    cout << "Input key: ";
    cin >> k;
    // 转化为64位
    uint64_t text = 0;
    stringstream s1;
    s1 << str;
    s1 >> text;
    uint64_t key;
    stringstream s2;
    s2 << k;
    s2 >> key;

    // 测试解密
    DES testEncrypt(text, key, 0);
    uint64_t cipher = testEncrypt.outputText();
    printf("Encryption:  %"PRIu64"\n", cipher);

    DES testDecrypt(cipher, key, 1);
    uint64_t plain = testDecrypt.outputText();
    printf("Decryption:  %"PRIu64"\n", plain);
    return 0;
}