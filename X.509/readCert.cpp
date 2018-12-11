#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <memory.h>
using namespace std;

int main(void) {
    FILE* fp = NULL;
    int iDataLen = 0;
    unsigned char *crlData = NULL;
    fp= fopen("./iNode.cer", "rb");
    cout << "Open file ";
    if (!fp) {
        cout << "Error\n";
        return -1;
    }
    cout << "Success\n";

    fseek(fp, 0L, SEEK_END);
    iDataLen = ftell(fp); //获取文件的大小
    cout << "DataLen: " << iDataLen << endl;
    fseek(fp, 0L, SEEK_SET);

    crlData = new unsigned char[iDataLen + 1];
    memset(crlData, 0x00, iDataLen + 1);

    fread(crlData, sizeof(unsigned char), iDataLen, fp);

    for (int i = 0; i < iDataLen; i++) {
        if (crlData[i] == 2) {
            if (crlData[i + 1] == 16) {
                string strNum;
                for (int j = 0; j < 16; j++) {
                    char str[3] = {0};
                    sprintf(str, "%02x", crlData[i + 2]); //将二进制的数据转变为十六进制的字符串
                    strNum += str;
                    i++;
                }
                cout << strNum << endl;
            } else {
                continue;
            }
        }
    }

    fclose(fp);
    delete[] crlData;
    crlData = NULL;
    return 0;
}