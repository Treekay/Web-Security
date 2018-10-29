#include "DES.cpp"
#include <fstream>

bitset<64> charToBitset(const char s[8]) {
	bitset<64> bits;
	for(int i=0; i<8; ++i)
		for(int j=0; j<8; ++j)
			bits[i*8+j] = ((s[i]>>j) & 1);
	return bits;
}

int main() {
    // 选择加密或解密
    int mode; // 0 Encrypt / 1 Decrypt
    cout << "Mode: ";
    cin >> mode;
    // 输入内容和密钥
    string s, k;
    cout << "Input: ";
    cin >> s;
    cout << "Key: ";
    cin >> k;
    bitset<64> plain = charToBitset(s.c_str());
    bitset<64> key = charToBitset(k.c_str());

    DES des1(plain, key, 0);
    auto cipher = des1.outputText();
    fstream file1;
    file1.open("cipher", ios::binary | ios::out);
    file1.write((char *)&cipher, sizeof(cipher));
    file1.close();

    // 解密
    bitset<64> temp;
    file1.open("cipher", ios::binary | ios::in);
    file1.read((char *)&temp, sizeof(temp));
    file1.close();

    DES des2(temp, key, 1);
    auto temp_plain = des2.outputText();
    file1.open("plain", ios::binary | ios::out);
    file1.write((char *)&temp_plain, sizeof(temp_plain));
    file1.close();
    
    return 0;
}