#include "MD5.cpp"

int main() {
    string msg;
    cout << "input: ";
    cin >> msg;
    cout << "md5: ";
    MD5 md5(msg);
    system("pause");
    return 0;
}