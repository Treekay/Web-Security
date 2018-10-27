#include "DES.cpp"

int main(void) {
    uint64_t text = 0x9AC534E927B160D;
    uint64_t key = 0x0000000000000000;

    // 测试加密
    DES testEncrypt(text, text, 0);
    uint64_t cipher = testEncrypt.outputText();
    printf("Encryption: %016llx\n", cipher);
    // 测试解密
    DES testDecrypt(text, text, 1);
    uint64_t plain = testDecrypt.outputText();
    printf("Decryption: %016llx\n", plain);
    return 0;
}