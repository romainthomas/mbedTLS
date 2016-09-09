/*
 *  PKCS#12 Personal Information Exchange Syntax
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PKCS7_C)

#include "mbedtls/pkcs7.h"
#include "mbedtls/asn1.h"
#include "mbedtls/cipher.h"

#include <string.h>

int pkcs7_parse_signeddata_params(mbedtls_asn1_buf *buff) {

  int ret;


  /*
   * SignedData ::= SEQUENCE {
   *  version Version,
   *  digestAlgorithms DigestAlgorithmIdentifiers,
   *  contentInfo ContentInfo,
   *
   *  certificates
   *    [0] IMPLICIT ExtendedCertificatesAndCertificates
   *    OPTIONAL,
   *
   *  Crls
   *    [1] IMPLICIT CertificateRevocationLists OPTIONAL,
   *  signerInfos SignerInfos }
   *
   * DigestAlgorithmIdentifiers ::=
   *  SET OF DigestAlgorithmIdentifier
   *
   * ContentInfo ::= SEQUENCE {
   *  contentType ContentType,
   *  content
   *    [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
   *
   * ContentType ::= OBJECT IDENTIFIER
   *
   * SignerInfos ::= SET OF SignerInfo
   */
  return 0;

}

#endif
