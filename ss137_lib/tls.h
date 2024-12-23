#ifndef SS137_TLS_HEADER_
#define SS137_TLS_HEADER_
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libgen.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/*****************************************************************************
 * DEFINES
 ******************************************************************************/

//SSL tuning parameters
#define MAX_TLS_DES          (100U)
#define VERIFY_DEPTH         (1U)

/** Converts seconds in milliseconds */
#define SEC_TO_MSEC(x) ((x)*1000U)

/*****************************************************************************
 * TYPEDEFS
 *****************************************************************************/

/** Struct holding the parameter used in a TLS session */
typedef struct
{
	bool_t  in_use;  /**< If the current descriptor is in use.*/
	int32_t socket;  /**< TCP socket of the current TLS connection.*/
	SSL    *ssl_ptr; /**< OpenSSL session.*/
} tls_descriptor_t;

/*****************************************************************************
 * VARIABLES
 *****************************************************************************/
/** List of ciphers. String is colon-separated i.e. "CIPHERA:CIPHERB:CIPHERC" */
const char allowed_ciphers[] = "ECDHE-RSA-AES256-GCM-SHA384";

/** Current OpenSSL context." */
static SSL_CTX *ctx = NULL;

/** The list of TLS descriptor available */
static tls_descriptor_t tls_descriptors[MAX_TLS_DES];

/** The listen socket of the server side */
static int32_t listen_sock = -1;

typedef enum
{
    TLS_SUCCESS = 0,
    TLS_ERROR = 1
} tls_error_code_t;

tls_error_code_t initClientTLS(uint32_t* const tls_id, const char* const ca_cert, const char* const key, const char* const cert);

tls_error_code_t connectTLS(const uint32_t tls_id, const char* const server_ip, const uint16_t remote_port);

tls_error_code_t initServerTLS(const uint16_t l_port, const char* const ca_cert, const char* const key, const char* const cert);
tls_error_code_t acceptTLS(uint32_t* const tls_id, char* const client_ip);

tls_error_code_t closeTLS(const uint32_t tls_id);

tls_error_code_t sendTLS(uint32_t* const bytes_sent, const uint8_t* const buf, const uint32_t buf_len, const uint32_t tls_id);
tls_error_code_t receiveTLS(uint32_t* const bytes_received, uint8_t* const buf, const uint32_t buf_len, const uint8_t timeout, const uint32_t tls_id);

tls_error_code_t exitTLS(void);


#endif