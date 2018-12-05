#ifndef _MD5_HPP_
#define _MD5_HPP_

#include <iostream>
#include <string>

using namespace std;

class MD5 {
public:
    MD5(string str);
    int* padding();

    int* getMD5();
private:
    string msg;
    int blockNum;   // 512位的块

};
#endif