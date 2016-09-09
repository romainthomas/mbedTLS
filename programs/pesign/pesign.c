
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/pkcs7.h>
#include <mbedtls/platform.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

//typedef signed_data_t {
//  int version;
//} signed_data_t;
/*
 * Load all data from a file into a given buffer.
 */
static int load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;
    long size;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( -1 );

    fseek( f, 0, SEEK_END );
    if( ( size = ftell( f ) ) == -1 )
    {
        fclose( f );
        return( -1 );
    }
    fseek( f, 0, SEEK_SET );

    *n = (size_t) size;

    if( *n + 1 == 0 ||
        ( *buf = mbedtls_calloc( 1, *n + 1 ) ) == NULL )
    {
        fclose( f );
        return( -1 );
    }

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );
        free( *buf );
        *buf = NULL;
        return( -1 );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    return( 0 );
}


static int get_SpcLink(unsigned char** p, const unsigned char *end) {

  printf("SpcLink\n");
  int ret;
  size_t tag;
  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0)
      return ret;

  // Dont parse it
  *p += tag;
  return 0;


}

static int get_SpcPeImageFlags(unsigned char** p, const unsigned char *end) {
  printf("get_SpcPeImageFlags\n");

  int ret;
  size_t len, tag;


  if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != MBEDTLS_ERR_ASN1_INVALID_DATA) {
    if (ret != 0) {
      return ret;
    }
  }
  (*p)++;


  return 0;
}

static int get_SpcPeImageData(unsigned char** p, const unsigned char *end) {
  printf("get_SpcPeImageData\n");

  int ret;
  size_t tag;

  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    return ret;

  if ((ret = get_SpcPeImageFlags(p, end)) != 0) {
    return ret;
  }

  if ((ret = get_SpcLink(p, end)) != 0) {
    return ret;
  }



  return 0;
}

static int get_SpcAttributeTypeAndOptionalValue(unsigned char** p, const unsigned char *end) {
  printf("get_SpcAttributeTypeAndOptionalValue\n");

  int ret;
  size_t tag;
  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    return ret;

  mbedtls_asn1_buf type;
  type.tag = **p;
  if ((ret = mbedtls_asn1_get_tag(p, end, &type.len, MBEDTLS_ASN1_OID)) != 0)
    return ret;
  type.p = *p;
  char oid_str[64] = { 0 };
  mbedtls_oid_get_numeric_string(oid_str, 64, &type);
  printf("%s\n", oid_str); // 1.3.6.1.4.1.311.2.1.15 (SPC_PE_IMAGE_DATAOBJ)
  *p += type.len;
  if ((ret = get_SpcPeImageData(p, end)) != 0)
    return ret;


  return 0;
}

static int get_messageDigest(unsigned char** p, const unsigned char *end) {
  printf("get_messageDigest\n");

  printf("%x\n", **p);
  int ret;
  size_t tag;
  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    return ret;

  //if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
  //  return ret;

  printf("%x\n", **p);

  char oid_str[64];
  mbedtls_asn1_buf alg_oid;
  if ((ret = mbedtls_asn1_get_alg_null(p, end, &alg_oid)) != 0) {
    return ret;
  }

  mbedtls_oid_get_numeric_string(oid_str, 64, &alg_oid);
  printf("Algo used: %s\n", oid_str);

  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_OCTET_STRING)) != 0)
    return ret;

  //TODO: Read hash

  *p += tag;




  return 0;
}

static int get_SpcIndirectDataContent(unsigned char** p, const unsigned char *end) {
  int ret = 0;
  size_t tag;

  printf("get_SpcIndirectDataContent\n");
  if ((ret = mbedtls_asn1_get_tag(p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    return ret;

  if ((ret = get_SpcAttributeTypeAndOptionalValue(p, end)) != 0) {
    return ret;
  }

  if ((ret = get_messageDigest(p, end)) != 0) {
    return ret;
  }
  return 0;
}


int main(void)
{
//mbedtls_oid_get_numeric_string
  unsigned char *p = NULL;
  size_t der_size = 48200;


  int ret = load_file("/home/romain/dev/mbedtls-2.3.0/programs/pesign/test.cert", &p, &der_size);

  if(ret != 0) {
    fprintf(stderr, "Error while loading cert\n");
  }
  printf("Der size = %d\n", der_size);


  const unsigned char *end = p + der_size;
  printf("end = %p\n", end);
  size_t tag;

  if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
    return ret;


  mbedtls_asn1_buf buf;
  buf.tag = *p;
  if ((ret = mbedtls_asn1_get_tag(&p, end, &buf.len, MBEDTLS_ASN1_OID)) != 0)
    fprintf(stderr, "Error while mbedtls_asn1_get_tag %d\n", ret);
  buf.p = p;
  char oid_str[64] = { 0 };
  mbedtls_oid_get_numeric_string(oid_str, 64, &buf);

  p += buf.len;
  //end = real_end;


  // SignedData Struct
  //
  if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_SIGNED_DATA, &buf) == 0) {
    printf("%s\n", oid_str);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0)
      return ret;


    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
      return ret;

    int version;
    if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0)
      return ret;
    printf("Version: %d\n", version);



    // Set of Algo (Only one for PE authenticode)
    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0)
      return ret;

    //end = real_end;
    mbedtls_asn1_buf alg_oid;
    if ((ret = mbedtls_asn1_get_alg_null(&p, end, &alg_oid)) != 0) {
      return ret;
    }
    mbedtls_oid_get_numeric_string(oid_str, 64, &alg_oid);
    printf("%s\n", oid_str);


    // Content Info
    //printf("*p = %x (%d)\n", *p, (p - end));

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0)
      return ret;


    // Content type
    mbedtls_asn1_buf content_type_oid;
    content_type_oid.tag = *p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &content_type_oid.len, MBEDTLS_ASN1_OID)) != 0)
      return ret;

    content_type_oid.p = p;
    mbedtls_oid_get_numeric_string(oid_str, 64, &content_type_oid);

    if (MBEDTLS_OID_CMP(MBEDTLS_SPC_INDIRECT_DATA_OBJID, &content_type_oid) != 0) {
      printf("%s != SPC_INDIRECT_DATA_OBJID\n", oid_str);
      return -1;
    }

    printf("%s\n", oid_str);
    p += content_type_oid.len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0)
      return ret;

    printf("*p = %x (%d)\n", *p, (p - end));
    if ((ret = get_SpcIndirectDataContent(&p, end)) != 0)
      return ret;


    if ((ret = mbedtls_asn1_get_tag(&p, end, &tag, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) != 0)
      return ret;
    printf("Parse crt\n");

    printf("*p = %x \n", *p);
    mbedtls_x509_crt ca;
    mbedtls_x509_crt_init(&ca);

    int i = 0;
    int b;
    do {

      mbedtls_x509_crt_init(&ca);
      b = mbedtls_x509_crt_parse_der(&ca, p + i , end - p);
      if (b != 0) {
        break;
      }
      char buffer[1024];
      mbedtls_x509_crt_info( buffer, 1024, "CRT: ", &ca);
      mbedtls_printf("%s\n", buffer );
      i += ca.raw.len;
    } while(b == 0);





    //end = p + tag;



  }



  //  return 1;
  //}



  //int version;

  //if((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0 ) {
  //  fprintf(stderr, "Error while mbedtls_asn1_get_int\n");
  //  return 1;
  //}

  //fprintf(stdout, "version: %d\n", version);

  return 0;
}
