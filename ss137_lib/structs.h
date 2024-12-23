#ifndef SS137_STRUCTS_HEADER_
#define SS137_STRUCTS_HEADER_
#include <stdint.h>
#include <time.h>

#include "constant.h"

// Triple-Key
typedef uint8_t KEY[8];
typedef KEY TRIPLE_KEY[3];

// TLS 연결 식별자
typedef uint32_t tls_des_t;

// 현재 세션 상태 구조체
typedef struct
{
    tls_des_t tlsID;            // TLS 세션 식별자
    uint8_t appTimeout;         // 타임아웃 시간(초)
    uint32_t transNum;          // 트랜잭션 횟수
    uint16_t peerSeqNum;        // 대상 엔티티 시퀀스 넘버
    uint32_t peerEtcsIDExp;     // 대상 엔티티 확장 ETCS ID
    struct timeval startTime;   // 마지막 수신 시간
} session_t;

// IP와 ETCS ID를 묶은 Entity 구조체
typedef struct
{
    uint32_t expEtcsId;
    char     ip[MAX_IP_LENGTH];
} kms_entity_id;

typedef struct
{
    char  rsaCACertificateFile[MAX_PATH_LENGTH];
    char  rsaKey[MAX_PATH_LENGTH];
    char  rsaCertificate[MAX_PATH_LENGTH];
    kms_entity_id myEntityId;   // 자신의 Entity Id
    kms_entity_id kmsEntitiesId[MAX_KMS_ENTITIES]; // KMC에 등록된 엔티티들의 아이디들 (RBC)
} ssl137_config;

/*
    관련 구조체들
*/
// 커맨드 타입 ENUM
typedef enum
{
	CMD_ADD_KEYS                 = 0,
	CMD_DELETE_KEYS              = 1,
	CMD_DELETE_ALL_KEYS          = 2,
	CMD_UPDATE_KEY_VALIDITIES    = 3,
	CMD_UPDATE_KEY_ENTITIES      = 4,
	CMD_REQUEST_KEY_OPERATION    = 5,
	CMD_REQUEST_KEY_DB_CHECKSUM  = 6,
	NOTIF_KEY_UPDATE_STATUS      = 7,
	NOTIF_ACK_KEY_UPDATE_STATUS  = 8,
	NOTIF_SESSION_INIT           = 9,
	NOTIF_END_OF_UPDATE          = 10,
	NOTIF_RESPONSE               = 11,
	NOTIF_KEY_OPERATION_REQ_RCVD = 12,
	NOTIF_KEY_DB_CHECKSUM        = 13,
	END_MSG_TYPE                 = 14
} msg_type_t;

// 커맨드 헤더
typedef struct
{
    uint32_t    msgLength;      // 메시지 길이
    uint8_t     version;        // 인터페이스 버전
    uint32_t    recIDExp;       // 수신자 확장 ETCS ID
    uint32_t    sendIDExp;      // 송신자 확장 ETCS ID
    uint32_t    transNum;       // 트랜잭션 수
    uint16_t    seqNum;         // 시퀀스 번호
    uint8_t     msgType;        // 메시지 타입
} msg_header_t;

// K-IDENTITY
typedef struct
{
    uint32_t genID;
    uint32_t serNum;
} k_ident_t;

typedef struct
{
    uint8_t     length;                     // 키 길이
    k_ident_t   kIdent;                     // K-IDENT
    uint32_t    etcsID;                     // KMAC 수신 대상 ETCSID
    uint8_t     kMAC[KMAC_SIZE];            // KMAC 키
    // K-ENTITY
    uint16_t    peerNum;                    // 대상 수
    uint32_t    peerID[MAX_PEER_NUM];       // 키에 연결된 대상 ID들
    // K-VALIDITY
    uint32_t    startValidity;              // 키 유효 시작 일
    uint32_t    endValidity;                // 키 유효 만료 일
} k_struct_t;

typedef struct
{
	k_ident_t kIdent;        // K-IDENTITY
	uint32_t  startValidity; // 유효 시작 일
	uint32_t  endValidity;	 // 유효 만료 일
} k_validity_t;

typedef struct 
{
    k_ident_t   kIdent;                 // K-IDENTITY
    uint16_t    peerNum;                // 연결된 대상 수
    uint32_t    peerID[MAX_PEER_NUM];   // 키에 연결된 대상 ID들
} k_entity_t;


// CMD_REQUEST_KEY_OPERATIN message struct typedef (5.3.9)
typedef struct 
{
    uint32_t etcsID;                // 
    uint8_t  reason;                // 
    uint32_t startValidity;         // 
    uint32_t endValidity;           // 
    uint16_t textLength;            // 
    char     text[MAX_TEXT_LENGTH]; // 
} cmd_req_key_op_t;

// Request Key Operation Reason (5.3.9)
typedef enum 
{
    NEW_TRAIN = 0,
    MOD_AREA = 1,
    RED_SCHED = 2,
    APPR_END_VAL = 3,
    END_KEY_OP = 4
} req_key_op_t;

// NOTIF_KEY_UPDATE_STATUS message struct typedef (5.3.11)
typedef struct 
{
    k_ident_t kIdent;
    uint8_t kStatus;
} key_update_status_t;

// Key Status (5.3.11)
typedef enum
{
    KEY_INST = 1,
    KEY_UP = 2,
    KEY_DEL = 3,
    END_KEY_STAT = 4
} k_status_t;

// Command/Request message payload를 유지하기 위한 구조체
typedef struct 
{
    msg_type_t msgType; // 메시지 타입
    uint16_t reqNum;    // kStructList, kIdentList, kValidityList or kEntityList 의 수
    k_struct_t kStructList[MAX_REQ_ADD_KEYS];
    k_ident_t kIdentList[MAX_REQ_DEL_KEYS];
    k_validity_t kValidityList[MAX_REQ_UPDATE];
    k_entity_t kEntityList[MAX_REQ_UPDATE];
    cmd_req_key_op_t reqKeyOpPayload;
    key_update_status_t keyUpStatusPayload;
} request_t;

// NOTIF_SESSION_INIT message struct typedef
typedef struct 
{
    uint8_t nVersion;
    uint8_t version[NUM_VERSION];
    uint8_t appTimeout;
} notif_session_init_t;

// NOTIF_RESPONSE message struct typedef
typedef struct 
{
    uint8_t reason;
    uint16_t reqNum;
    uint8_t notificationList[MAX_REQ_NOTIF];
} notif_response_t;

// Response reason of NOTIF_RESPONSE (5.3.13)
typedef enum
{
	RESP_OK               = 0,
	RESP_NOT_SUPPORTED    = 1,
	RESP_WRONG_LENGTH     = 1,
	RESP_WRONG_SENDER_ID  = 3,
	RESP_WRONG_REC_ID     = 4,
	RESP_WRONG_VERSION    = 5,
	RESP_KEY_BD_FAULT     = 6,
	RESP_MSG_PROC_FAULT   = 7,
	RESP_WRONG_CHKSUM     = 8,
	RESP_WRONG_SEQ_NUM    = 9,
	RESP_WRONG_TRANS_NUM  = 10,
	RESP_WRONG_FORMAT     = 11,
	RESP_TIMEOUT          = 12,
	END_RESP_REASON       = 13
} response_reason_t;

/** Notification status of NOTIF_RESPONSE (see ref. SUBSET-137 5.3.13) */
typedef enum
{
	REQ_SUCCESS      = 0,
	UNKNOWN_KEY      = 1,
	MAX_KEY          = 2,
	KEY_EXIST        = 3,
	KEY_CORRUPTED    = 4,
	WRONG_ID         = 5,
	END_NOTIF_REASON = 6
} notif_reason_t;

/** NOTIF_KEY_OPERAION_REQ_RCVD message struct typedef (see ref. SUBSET-137 5.3.16) */
typedef struct
{
	uint16_t maxTime; /**< Maximum time in hours required to respond to the key operation request.*/
} notif_key_op_req_rcvd_t;

/** NOTIF_KEY_DB_CHECKSUM message struct typedef (see ref. SUBSET-137 5.3.17) */
typedef struct
{
	uint8_t checksum[CHECKSUM_SIZE]; /**< The checksum of the KMAC entity's key database.*/
} notif_key_db_checksum_t;

/** Struct holding all of response */
typedef struct
{
	msg_type_t              msgType;           /**< The type of the response.*/
	notif_response_t        notifPayload;      /**< The NOTIF_RESPONSE body.*/
	notif_key_db_checksum_t dbChecksumPayload; /**< The NOTIF_KEY_DB_CHECKSUM body.*/
	notif_key_op_req_rcvd_t keyOpRecvdPayload; /**< The NOTIF_KEY_OPERAION_REQ_RCVD body.*/
} response_t;

/**
 * Stores data about stream read from socket.
 */
typedef struct
{
	uint32_t curPos;               /**< Current read position in the buffer. */
	uint32_t validBytes;           /**< Valid bytes of the buffer. */
	uint8_t  buffer[MSG_MAX_SIZE]; /**< Read stream buffer. */
} read_stream_t;

/**
 * Stores data about stream to be write on socket.
 */
typedef struct
{
	uint32_t  curSize;              /**< Current size of the stream. */
	uint8_t   buffer[MSG_MAX_SIZE]; /**< Write stream buffer. */
} write_stream_t;

typedef struct
{
	uint32_t curPos;               /**< Current read position in the buffer. */
	uint32_t validBytes;           /**< Valid bytes of the buffer. */
	uint8_t  buffer[MSG_MAX_SIZE]; /**< Read stream buffer. */
} read_stream_t;

/**
 * Stores data about stream to be write on socket.
 */
typedef struct
{
	uint32_t  curSize;              /**< Current size of the stream. */
	uint8_t   buffer[MSG_MAX_SIZE]; /**< Write stream buffer. */
} write_stream_t;


#endif