#ifndef SS137_CONSTANT_HEADER_
#define SS137_CONSTANT_HEADER_

///////////////// NET UTILS /////////////////////////////////////
/** Message max size (see ref. SUBSET-137 5.3.2.4) */
#define MSG_MAX_SIZE (5000U)
///////////////// NET UTILS /////////////////////////////////////

/** Default ss137 tcp port (see ref SUBSET137 7.3.1.2)*/
#define SS137_TCP_PORT    (7912U)

/** Max ip length in ASCII*/
#define MAX_IP_LENGTH     (16U)

/** Max kms entities configurable*/
#define MAX_KMS_ENTITIES  (100U)

/** Max length of certificate and key path*/
#define MAX_PATH_LENGTH   (256U)


/////////////////////////////// MSG DEFINES ///////////////////////////////////
/*****************************************************************************
 * DEFINES
 ******************************************************************************/

/** Number of supported version in the current release (see ref. SUBSET-137 5.3.13) */
#define NUM_VERSION       (1U) 

/** Application timeout defined by the peer entity (see ref. SUBSET-137 5.3.13) */
#define APP_TIMEOUT_PEER_DEF (0xFFU)

/** The key length in bytes (see ref. SUBSET-137 5.3.4.1) */
#define KMAC_SIZE         (24U)

/** @name Number of peer entities associated with an authentication key (see ref. SUBSET-137 5.3.4.1)
 **@{*/
#define MIN_PEER_NUM      (1U)
#define MAX_PEER_NUM      (1000U)
/**@}*/

/** @name Number of k-struct in a CMD_ADD_KEYS message (see ref. SUBSET-137 5.3.4.1)
 **@{*/
#define MIN_REQ_ADD_KEYS  (1U)
#define MAX_REQ_ADD_KEYS  (100U)
/**@}*/

/** @name Number of k-identifier in a CMD_DEL_KEYS message (see ref. SUBSET-137 5.3.5)
 **@{*/
#define MIN_REQ_DEL_KEYS  (1U)
#define MAX_REQ_DEL_KEYS  (500U)
/**@}*/

/** @name Number of k-validity in a CMD_UPDATE_KEY_VALIDITIES (see ref. SUBSET-137 5.3.7)
	or k-entitites in a CMD_UPDATE_KEy_ENTITIES message (see ref. SUBSET-137 5.3.8)
	**@{*/
#define MIN_REQ_UPDATE  (1U)
#define MAX_REQ_UPDATE  (250U)
/**@}*/

/** Max number ot notification struct in a NOTIF_RESPONSE message (see ref. SUBSET-137 5.3.15) */
#define MAX_REQ_NOTIF   (500U)

/** Max text length in a CMD_REQUEST_KEY_OPERATION message (see ref. SUBSET-137 5.3.9) */
#define MAX_TEXT_LENGTH (1000U)

/** Size of the md4 checksum (see ref. SUBSET-137 5.3.9) */
#define CHECKSUM_SIZE (20U) 

/** Size of k-identifier struct (see ref. SUBSET-137 5.3.4.2) */
#define K_IDENT_SIZE      (2*sizeof(uint32_t))

/** Minimun size of a k-struct  (see ref. SUBSET-137 5.3.4.1) */
#define K_STRUCT_MIN_SIZE (K_IDENT_SIZE + 3*sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + KMAC_SIZE*sizeof(uint8_t))

/** Size of k-validity struct (see ref. SUBSET-137 5.3.7.1) */
#define K_VALIDITY_SIZE   (K_IDENT_SIZE + 2*sizeof(uint32_t))

/** Minimum size of k-entity struct (see ref. SUBSET-137 5.3.8.1) */
#define K_ENTITY_MIN_SIZE (K_IDENT_SIZE + sizeof(uint16_t))

/** Message header size, 20 bytes (see ref. SUBSET-137 5.3.3) */
#define MSG_HEADER_SIZE      (4*sizeof(uint32_t) + sizeof(uint16_t) + 2*sizeof(uint8_t))

/** Message payload max size */
#define MSG_PAYLOAD_MAX_SIZE (MSG_MAX_SIZE - MSG_HEADER_SIZE) /* 4980 bytes */

/** Size of the number of request field */
#define REQ_NUM_SIZE      (sizeof(uint16_t))

/** @name Message tipical size
 **@{*/
#define CMD_ADD_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_DEL_KEYS_MIN_SIZE        (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_DEL_ALL_KEYS_SIZE        (MSG_HEADER_SIZE)
#define CMD_UP_KEY_VAL_MIN_SIZE      (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_UP_KEY_ENT_MIN_SIZE      (MSG_HEADER_SIZE+REQ_NUM_SIZE)
#define CMD_REQUEST_KEY_OP_MIN_SIZE  (MSG_HEADER_SIZE+3*sizeof(uint32_t)+sizeof(uint8_t)+sizeof(uint16_t))
#define CMD_REQUEST_KEY_DB_CK_SIZE   (MSG_HEADER_SIZE)
#define NOTIF_KEY_UP_STATUS_SIZE     (MSG_HEADER_SIZE+K_IDENT_SIZE+sizeof(uint8_t))
#define NOTIF_ACK_KEY_UP_STATUS_SIZE (MSG_HEADER_SIZE)
#define NOTIF_SESSION_INIT_SIZE      (MSG_HEADER_SIZE + 3*sizeof(uint8_t))
#define NOTIF_END_UPDATE_SIZE        (MSG_HEADER_SIZE)
#define NOTIF_RESPONSE_MIN_SIZE      (MSG_HEADER_SIZE+sizeof(uint8_t)+REQ_NUM_SIZE)
#define NOTIF_KEY_OP_REQ_RCVD_SIZE   (MSG_HEADER_SIZE+sizeof(uint16_t))
#define NOTIF_KEY_DB_CHECKSUM_SIZE   (MSG_HEADER_SIZE+CHECKSUM_SIZE)
/**@}*/

#endif