#include "MD5.hpp"

MD5::MD5(string str) {
    msg = str;
}

int* MD5::padding() {
    // 512位一个块, 即64个字节(一个字节8位), 最后的块填充位数1~512的100....0标识
    blockNum = (msg.length() + 8) / 64 + 1;
    // 最终输出的十六进制内容每个字符为4位, 则有 64 / 4 = 16个十六进制数
    int len = blockNum * 16;
    int* outputStr = new int[len];
    
}


int* MD5::getMD5(){
    padding();

}