#ifndef _CERTPARSE_H_
#define _CERTPARSE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Certificate::=SEQUENCE{
        tbsCertificate      TBSCertificate,
        signatureAlgorithm  AlgorithmIdentifier,
        signatureValue      BIT STRING
    }
}*/
void getCertificate();
/*
    TBSCertificate::=SEQUENCE{
        version           [0]   EXPLICIT Version DEFAULT v1,
        serialNumber            CertificateSerialNumber,
        signature               AlgorithmIdentifier,
        issuer                  Name,
        validity                Validity,
        subject                 Name,
        subjectPublicKeyInfo    SubjectPublicKeyInfo,
        issuerUniqueID    [1]   IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID   [2]   IMPLICIT UniqueIdentifier OPTIONAL,
        extensions        [3]   EXPLICIT Extensions OPTIONAL
    }
*/
void getTBSCertificate();
void getVersion();
void getSerialNum();
void getValidty();
void getSubjectPublicKeyInfo();
void skipOptional();
/*
    AlgorithmIdentifier::=SEQUENCE{
        algorithm       OBJECT IDENTIFIER,
        parameters      ANY DEFINED BY algorithm OPTIONAL
    }
*/
void getSignatureAlgorithm();
void getSignatureValue();

void parseAlgorithmIdentifier();
void parseName();

void getOID(unsigned char*, int, char*);
void getTime(char* str);
void getAlgorithm(char *oid);
void getIssuer(char *issuer);
int getLength();

#endif // !_CERTPARSE_H_