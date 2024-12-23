#include "server.h"

uint8_t snd_buf[2048];
uint8_t rcv_buf[2048];
tls_descriptor_t tls_id = 0x00000001;
ss137_config config = {
    "",
    "",
    "",
    {
        0x00000000,
        "127.0.0.1"
    },
    [
        {
            0x11223344,
            "127.0.0.1"
        }
    ]
}

void serverHandler(void) {
    request_t request;
    response_t response;
    bool_t stop = FALSE;
    uint32_t i = 0U;
    uint32_t exp_etcs_id = 0U;

    if(startServerTLS() == ERROR) {
        return;
    }

    while(1) {
        session_t session;
        memset(&session, 0, sizeof(session_t));

        if(listenForTLSClient(&session.tlsID, &exp_etcs_id) != SUCCESS)
        {
            exit(1);
        }

        if(initAppSession(&session, 0xff, exp_etcs_id) != SUCCESS)
        {
            closeTLSConnection(session.tlsID);
        }

        while(stop == FALSE)
        {
            if(waitForRequestFromKMCToKMAC(&request, &session) != SUCCESS)
            {
                stop = TRUE;
                continue;
            }
            
            log_print("Request received : %d\n", request.msgType);

            switch(request.msgType)
            {
                case(NOTIF_END_OF_UPDATE):
                    stop = TRUE;
                    break;
                case(CMD_REQUEST_KEY_DB_CHECKSUM):
                    for(i=0U; i < sizeof(response.dbChecksumPayload.checksum); i++)
                    {
                        response.dbChecksumPayload.checksum[i] = i;
                    }
                    sendNotifKeyDBChecksum(&response, &session);
                    break;
                case(CMD_DELETE_ALL_KEYS):
                    response.notifPayload.reason = RESP_OK;
                    response.notifPayload.reqNum = 0;
                    if(sendNotifResponse(&response, &session) != SUCCESS)
                    {
                        stop = TRUE;
                        continue;
                    }
                    break;
                default:
                    response.notifPayload.reason = RESP_OK;
                    response.notifPayload.reqNum = request.reqNum;

                    for(i = 0U; i < request.reqNum; i++)
                    {
                        response.notifPayload.notificationList[i] = 0U;
                    }

                    if(sendNotifResponse(&response, &session) != SUCCESS)
                    {
                        stop = TRUE;
                        log_print("End of update message received \n");\
                        continue;
                    }

                    break;
            }

            session.transNum++;
            request.reqNum = 0;
            sleep(5U);
        }

        stop = FALSE;
        closeTLSConnection(session.tlsID);
    }

    return 0;
}