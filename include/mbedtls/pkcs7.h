#ifndef MBEDTLS_PKCS7_H
#define MBEDTLS_PKCS7_H

#include "asn1.h"

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

int pkcs7_parse_signeddata_params(mbedtls_asn1_buf *buff);

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */

