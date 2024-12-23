#ifndef SS137_LIB_HEADER_
#define SS137_LIB_HEADER_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "structs.h"
#include "constant.h"
#include "utils.h"
#include "tls.h"

error_code_t startClientTLS(tls_des_t* const tls_id);
error_code_t startServerTLS(void);
error_code_t connectToTLSServer(const tls_des_t const tls_id, const char* const server_ip);
error_code_t listenForTLSClient(tls_det_t* const tls_id, uint32_t* const exp_etcs_id);
void closeTLSConnection(const tls_des_t tls_id);
error_code_t waitForRequestFromKMCToKMAC(request_t* const request, session_t const curr_session);
error_code_t initAppSession(session_t* const curr_session, const uint8_t app_timeout, const uint32_t peer_etcs_id_exp);
error_code_t endAppSession(const session_t* const curr_session);


/* Custom Function */



#endif