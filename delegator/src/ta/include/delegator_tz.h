#ifndef TA_DELEGATOR_TZ_H
#define TA_DELEGATOR_TZ_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_DELEGATOR_TZ_UUID \
	{ 0x8aaaf200, 0x2450, 0x11e4, \
	{ 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69}}

/* The function IDs implemented in this TA */
#define TA_INSTALL_KEYS		0
#define TA_HAS_KEYS         1
#define TA_DEL_KEYS         2
#define TA_SIGN_ECC         3
#define TA_SIGN_RSA         4
#define TA_DECRYPT          5

#endif /*TA_DELEGATOR_TZ_H*/
