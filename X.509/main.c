#include "X509Parser.c"

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        printf("Please input the file\n");
    } else {
        cert = fopen(argv[1], "rb");
        if (!cert) {
            printf("Open file error!\n");
        } else {
            getCertificate();
            fclose(cert);
        }
    }
    return 0;
}