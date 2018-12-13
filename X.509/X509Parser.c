#include "X509Parser.h"

FILE *cert;

/* Certificate */
void getCertificate() {
    // Type
    fgetc(cert);    
    // Length
    getLength();    
    // Value
    getTBSCertificate();    
    getSignatureAlgorithm();
    getSignatureValue();
}

/* TBSCertificate */
void getTBSCertificate() {
    // Type
    fgetc(cert); 
    // Length
    getLength(); 
    // Value
    getVersion();           /* version */

    getSerialNum();         /* serialNumber */

    printf("Signature:\n"); /* signature */
    fgetc(cert);   
    getLength();
    parseAlgorithmIdentifier();

    printf("Issuer:\n");    /* issuer */
    parseName();

    printf("Validity:\n");  /* validity */
    getValidty();

    printf("Subject:\n");   /* subject */
    parseName();

    getSubjectPublicKeyInfo(); /* subjectPublicKeyInfo */

    /* issuerUniqueID [OPTIONAL] */
    /* subjectUniqueID [OPTIONAL] */
    /* extensions [OPTIONAL] */
    skipOptional(); // skip optional
}

/* SignatureAlgorithm */
void getSignatureAlgorithm() {
    printf("SignatureAlgorithm: \n", ftell(cert));
    getLength();
    parseAlgorithmIdentifier();
}

/* SignatureValue */
void getSignatureValue() {
    fgetc(cert);
    int len = getLength();
    unsigned char bytes[4096] = {0};
    fread(bytes, 1, len, cert);
    printf("SignatureValue: 0x");
    for (int i = 0; i < len; ++i) {
        printf("%x", bytes[i]);
    }
    printf("\n");
}

void getVersion() {
    unsigned char type = fgetc(cert);   // Type
    if (type >= 0xA0) { // 判断该字段是否存在
        getLength();                    // Length
        fgetc(cert);                    // Value { Type
        int t = getLength();            //         Length
        int version = 1;                //         Value }
        for (int i = 0; i < t; ++i) {  
            version += (int)fgetc(cert) << ((t - i - 1) * 8);
        }
        printf("Version: %d\n", version);
        fgetc(cert); 
    } else {
        printf("Version: 1\n");
    }
}

void getSerialNum() {
    unsigned char bytes[4096] = {0};
    int len = getLength();        // Length
    fread(bytes, 1, len, cert);   // Value
    printf("Serial Number: 0x");
    for (int i = 0; i < len; ++i) {
        printf("%x", bytes[i]);
    }
    printf("\n");
}

void getValidty() {
    char str[100];
    fgetc(cert);            // Type
    getLength();            // Length
    getTime(str);           // Value
    printf("\tStartTime: %s\n", str);
    getTime(str);
    printf("\tEndTime: %s\n", str);
}

void getSubjectPublicKeyInfo() {
    printf("SubjectPublicKeyInfo:\n");
    int len;
    unsigned char bytes[4096] = {0};
    char str[100];

    fgetc(cert);
    getLength();
    fgetc(cert);
    getLength();

    fgetc(cert);
    len = getLength();
    fread(bytes, 1, len, cert);
    getOID(bytes, len, str);
    printf("\tecPublicKey %s\n", str);

    fgetc(cert);
    len = getLength();
    fread(bytes, 1, len, cert);
    getOID(bytes, len, str);
    printf("\tprime256v1 %s\n", str);

    fgetc(cert);
    len = getLength();
    fread(bytes, 1, len, cert);
    printf("\tSubjectPublicKey: 0x");
    for (int i = 0; i < len; ++i) {
        printf("%x", bytes[i]);
    }
    printf("\n");
}

void skipOptional() {
    unsigned char type;
    while ((type = fgetc(cert)) > 0xA0) {
        switch (type)  {
            case 0xA1:
                printf("IssuerUniqueID: ...\n");
                break;
            case 0xA2:
                printf("SubjectUniqueID: ...\n");
                break;
            case 0xA3:
                printf("Extensions: ...\n");
                break;
            default:
                break;
        }
        fseek(cert, getLength(), SEEK_CUR);
    }
}

int getLength() {
    unsigned char c = fgetc(cert);
    int length = 0;
    if (c & 0x80) {
        int t = c - 0x80;
        for (int i = 0; i < t; ++i) {
            length += (int)fgetc(cert) << ((t - i - 1) * 8);
        }
    } else {
        length = c;
    }
    return length;
}

void parseAlgorithmIdentifier() {
    fgetc(cert);
    int len = getLength();
    unsigned char bytes[4096] = {0};
    fread(bytes, 1, len, cert);

    char str[100];
    getOID(bytes, len, str);
    printf("\tAlgorithm: %s", str);
    getAlgorithm(str);
    printf("%s\n", str);

    // param
    if (fgetc(cert) != 0x05) {
        fseek(cert, getLength(), SEEK_CUR);
        printf("\tParameter: ...\n");
    } else {
        fgetc(cert);
        printf("\tParameter: NULL\n");
    }
}

void parseName() {
    fgetc(cert);    // Type
    int len = getLength() + ftell(cert);    // Length
    unsigned char bytes[4096] = {0};
    char str[100];
    while (ftell(cert) < len) { // Value
        fgetc(cert);  // set
        getLength();
        fgetc(cert);  // sequence
        getLength();

        // AttributeType
        fgetc(cert);
        int l = getLength();
        fread(bytes, 1, l, cert);
        getOID(bytes, l, str);
        printf("\t%-10s ", str);
        getIssuer(str);
        printf("%-25s", str);
        memset(str, 0, 100);

        // AttributeValue
        fgetc(cert);
        l = getLength();
        fread(str, 1, l, cert);
        printf("%s\n", str);
    }
}

void getOID(unsigned char* oid, int len, char* out) {
    int index = 0;
    int b = oid[0] % 40;
    int a = (oid[0] - b) / 40;
    sprintf(out, "%d.%d", a, b);
    for (int i = 1; i < len; ++i) {
        if (oid[i] < 128) {
            sprintf(out + strlen(out), ".%d", oid[i]);
        } else {
            int res = 0;
            while (oid[i] >= 128) {
                res = res * 128 + oid[i++] - 128;
            }
            res = res * 128 + oid[i];
            sprintf(out + strlen(out), ".%d", res);
        }
    }
}

void getTime(char *str) {
    memset(str, 0, 100);
    char type = fgetc(cert);
    int l = getLength();
    fread(str, 1, l, cert);
    if (type == 0x17) {
        sprintf(str, "%s (UTCTime)", str);
    } else {
        sprintf(str, "%s (GeneralizedTime)", str);
    }
}

void getAlgorithm(char *oid) {
    // RFC5698
    if (!strcmp("1.2.840.10040.4.1", oid))
        sprintf(oid, "dsa");
    else if (!strcmp("1.3.14.3.2.26", oid))
        sprintf(oid, "sha-1");
    else if (!strcmp("2.16.840.1.101.3.4.2.4", oid))
        sprintf(oid, "sha-224");
    else if (!strcmp("2.16.840.1.101.3.4.2.1", oid))
        sprintf(oid, "sha-256");
    else if (!strcmp("2.16.840.1.101.3.4.2.2", oid))
        sprintf(oid, "sha-384");
    else if (!strcmp("2.16.840.1.101.3.4.2.3", oid))
        sprintf(oid, "sha-512");
    else if (!strcmp("1.2.840.113549.1.1.1", oid))
        sprintf(oid, "rsa");
    else if (!strcmp("1.2.840.113549.2.2", oid))
        sprintf(oid, "md2");
    else if (!strcmp("1.2.840.113549.2.5", oid))
        sprintf(oid, "md5");
    else if (!strcmp("1.2.840.113549.1.1.2", oid))
        sprintf(oid, "md2WithRSAEncryption");
    else if (!strcmp("1.2.840.113549.1.1.4", oid))
        sprintf(oid, "md5WithRSAEncryption");
    else if (!strcmp("1.2.840.113549.1.1.5", oid))
        sprintf(oid, "sha1WithRSAEncryption");
    else if (!strcmp("1.2.840.113549.1.1.11", oid))
        sprintf(oid, "sha256WithRSAEncryption");
    else if (!strcmp("1.2.840.113549.1.1.12", oid))
        sprintf(oid, " sha384WithRSAEncryption");
    else if (!strcmp("1.2.840.113549.1.1.13", oid))
        sprintf(oid, "sha512WithRSAEncryption");
    else if (!strcmp("1.2.840.10040.4.3", oid))
        sprintf(oid, "sha1WithDSA");
    else
        sprintf(oid, "<Unknown>");
}

void getIssuer(char *issuer) {
    if (!strcmp("2.5.4.6", issuer))
        sprintf(issuer, "countryName");
    else if (!strcmp("2.5.4.10", issuer))
        sprintf(issuer, "organizationName");
    else if (!strcmp("2.5.4.3", issuer))
        sprintf(issuer, "commonName");
    else if (!strcmp("2.5.4.11", issuer))
        sprintf(issuer, "organizationalUnitName");
    else if (!strcmp("2.5.4.7", issuer))
        sprintf(issuer, "localityName");
    else if (!strcmp("2.5.4.8", issuer))
        sprintf(issuer, "stateOrProvinceName");
    else
        sprintf(issuer, "<Unknown>");
}