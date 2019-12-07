/**
********************************************************************************************************
 * @file        test_atecc508a.c
 * @brief
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <ockam/define.h>
#include <ockam/error.h>

#include <ockam/vault.h>
#include <ockam/vault/tpm/microchip.h>

#include <cryptoauthlib/lib/cryptoauthlib.h>
#include <cryptoauthlib/lib/atca_cfgs.h>
#include <cryptoauthlib/lib/atca_iface.h>
#include <cryptoauthlib/lib/atca_device.h>


/*
 ********************************************************************************************************
 *                                                DEFINES                                               *
 ********************************************************************************************************
 */

#define TEST_ATECC508A_PMS_SIZE                     32u
#define TEST_ATECC508A_PUB_KEY_SIZE                 64u
#define TEST_ATECC508A_RAND_NUM_SIZE                32u
#define TEST_ATECC508A_HKDF_KEY_SIZE                32u
#define TEST_ATECC508A_PROTOCOL_SALT_SIZE           16u

#define TEST_ATECC508A_AES_IV_SIZE                  12u
#define TEST_ATECC508A_AES_ADD_SIZE                 20u
#define TEST_ATECC508A_AES_KEY_SIZE                 16u
#define TEST_ATECC508A_AES_TAG_SIZE                 16u
#define TEST_ATECC508A_AES_DATA_SIZE                60u


/*
 ********************************************************************************************************
 *                                               CONSTANTS                                              *
 ********************************************************************************************************
 */

/**
 *******************************************************************************
 * @enum    TEST_ATECC508A_PUB_KEY_e
 * @brief   List of public keys to manage
 *******************************************************************************
 */

typedef enum {
    TEST_ATECC508A_PUB_KEY_STATIC   = 0,                        /*!< Static Key in ATECC508A                          */
    TEST_ATECC508A_PUB_KEY_EPHEMERAL,                           /*!< Ephemeral Key in ATECC508A                       */
    TOTAL_TEST_ATECC508A_PUB_KEY                                /*!< Total number of keys handled                     */
} TEST_ATECC508A_PUB_KEY_e;


/*
 ********************************************************************************************************
 *                                               DATA TYPES                                             *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                          FUNCTION PROTOTYPES                                         *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            GLOBAL VARIABLES                                          *
 ********************************************************************************************************
 */

ATCAIfaceCfg atca_iface_i2c = {
    .iface_type                 = ATCA_I2C_IFACE,
    .devtype                    = ATECC508A,
    {
        .atcai2c.slave_address  = 0xB0,
        .atcai2c.bus            = 1,
        .atcai2c.baud           = 100000,
    },
    .wake_delay                 = 1500,
    .rx_retries                 = 20
};

VAULT_MICROCHIP_CFG_s atecc508a_cfg = {
    .iface                      = VAULT_MICROCHIP_IFACE_I2C,
    .iface_cfg                  = &atca_iface_i2c,
};

OCKAM_VAULT_CFG_s vault_cfg =
{
    .p_tpm                       = &atecc508a_cfg,
    .p_host                      = 0
};

uint8_t g_pub_key[TEST_ATECC508A_PUB_KEY_SIZE * TOTAL_TEST_ATECC508A_PUB_KEY];

                                                                /* Global protocol salt defined for all Ockam comms   */
uint8_t g_protocol_salt[TEST_ATECC508A_PROTOCOL_SALT_SIZE] = {
    0xfb, 0x49, 0xc1, 0x74, 0x68, 0x73, 0xc7, 0xf9,
    0x7b, 0x8f, 0x24, 0x5b, 0xdf, 0x77, 0xdb, 0xd8
};

uint8_t g_aes_key[TEST_ATECC508A_AES_KEY_SIZE] = {              /* Known AES test key value                           */
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

uint8_t g_aes_add[TEST_ATECC508A_AES_ADD_SIZE] = {              /* Known additional authentication data for AES GCM   */
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};

uint8_t g_aes_iv[TEST_ATECC508A_AES_IV_SIZE] = {                /* Known input vector for AES GCM                     */
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};

uint8_t g_aes_tag[TEST_ATECC508A_AES_TAG_SIZE] = {              /* Expected tag value from AES GCM encrypt            */
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
    0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
};

uint8_t g_aes_plain_text[TEST_ATECC508A_AES_DATA_SIZE] = {      /* Plain text test value for AES GCM encrypt/decrypt  */
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39
};

uint8_t g_aes_encrypt_hash[TEST_ATECC508A_AES_DATA_SIZE] = {    /* Expected AES GCM encryption of plain text data     */
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
    0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
    0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
    0x3d, 0x58, 0xe0, 0x91
};


/*
 ********************************************************************************************************
 *                                           GLOBAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

void print_array(uint8_t* p_array, uint32_t size);


/*
 ********************************************************************************************************
 *                                            LOCAL FUNCTIONS                                           *
 ********************************************************************************************************
 */


/**
 ********************************************************************************************************
 *                                             main()
 *
 * @brief   Main point of entry for ATECC508A test
 *
 ********************************************************************************************************
 */

void main (void)
{
    OCKAM_ERR err;
    uint8_t i;

    uint8_t rand_num[TEST_ATECC508A_RAND_NUM_SIZE];
    uint8_t pms_static[TEST_ATECC508A_PMS_SIZE];
    uint8_t pms_ephemeral[TEST_ATECC508A_PMS_SIZE];

    uint8_t *p_key_static = &g_pub_key[TEST_ATECC508A_PUB_KEY_STATIC * TEST_ATECC508A_PUB_KEY_SIZE];
    uint8_t *p_key_ephemeral = &g_pub_key[TEST_ATECC508A_PUB_KEY_EPHEMERAL * TEST_ATECC508A_PUB_KEY_SIZE];


    /* ---------- */
    /* Vault Init */
    /* ---------- */

    err = ockam_vault_init((void*) &vault_cfg);                 /* Initialize Vault                                   */
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vauilt Init failed\r\n");
    }

    /* ------------------------ */
    /* Random Number Generation */
    /* ------------------------ */

    err = ockam_vault_random((uint8_t*) &rand_num,              /* Generate a random number                           */
                             TEST_ATECC508A_RAND_NUM_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault Random failed\r\n");
    }

    printf("Random Number Generation Output:\r\n");

    for(i = 1; i <= TEST_ATECC508A_RAND_NUM_SIZE; i++) {
        printf("%02X ", rand_num[i-1]);
        if(i % 8 == 0) {
            printf("\r\n");
        }
    }

    /* -------------- */
    /* Key Generation */
    /* -------------- */

    err = ockam_vault_key_gen(OCKAM_VAULT_KEY_STATIC,           /* Generate a static key                              */
                              p_key_static,
                              TEST_ATECC508A_PUB_KEY_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault Static Key Generate Failed\r\n");
    } else {
        printf("Key: Sucessfully generated a static key\r\n");
    }

    err = ockam_vault_key_gen(OCKAM_VAULT_KEY_EPHEMERAL,        /* Generate an ephemrmal key                          */
                              p_key_ephemeral,
                              TEST_ATECC508A_PUB_KEY_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault Ephemeral Key Generate Failed\r\n");
    } else {
        printf("Key: Sucessfully generated an ephemeral key\r\n");
    }

    /* ------------ */
    /* Key Retrival */
    /* ------------ */

    err = ockam_vault_key_get_pub(OCKAM_VAULT_KEY_STATIC,       /* Get the static public key                          */
                                  p_key_static,
                                  TEST_ATECC508A_PUB_KEY_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault Get Static Public Key Failed\r\n");
    } else {
        printf("Key: Sucessfully retrieved static key\r\n");
        print_array(p_key_static, TEST_ATECC508A_PUB_KEY_SIZE);
    }

    err = ockam_vault_key_get_pub(OCKAM_VAULT_KEY_EPHEMERAL,    /* Get the ephemrmal public key                       */
                                  p_key_ephemeral,
                                  TEST_ATECC508A_PUB_KEY_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault Get Ephemeral Public Key Failed\r\n");
    } else {
        printf("Key: Sucessfully retrieved ephemeral public key\r\n");
        print_array(p_key_ephemeral, TEST_ATECC508A_PUB_KEY_SIZE);
    }

    /* ----------------- */
    /* ECDH Calculations */
    /* ----------------- */

    err = ockam_vault_ecdh(OCKAM_VAULT_KEY_STATIC,              /* Calculate ECDH with static private/ephemeral pub   */
                           p_key_ephemeral,
                           TEST_ATECC508A_PUB_KEY_SIZE,
                           &pms_static[0],
                           TEST_ATECC508A_PMS_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Static Private/Ephemeral Public ECDH Failed\r\n");
    } else {
        printf("ECDH: Static Private/Ephemeral Public\r\n");
        print_array(&pms_static[0], TEST_ATECC508A_PMS_SIZE);
    }

    err = ockam_vault_ecdh(OCKAM_VAULT_KEY_EPHEMERAL,          /* Calculate ECDH with static private/ephemeral pub    */
                           p_key_static,
                           TEST_ATECC508A_PUB_KEY_SIZE,
                           &pms_ephemeral[0],
                           TEST_ATECC508A_PMS_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Static Public/Ephemeral Private ECDH Failed\r\n");
    } else {
        printf("ECDH: Static Public/Ephemeral Private\r\n");
        print_array(&pms_ephemeral[0], TEST_ATECC508A_PMS_SIZE);
    }

    for(i = 0; i < TEST_ATECC508A_PMS_SIZE; i++) {
        if(pms_static[i] != pms_ephemeral[i]) {
            printf("Error: Ockam Vault PMS do not match!\r\n");
            break;
        }
    }

    /* ----------------- */
    /* HKDF Calculations */
    /* ----------------- */

    uint8_t hkdf_key[TEST_ATECC508A_HKDF_KEY_SIZE];

    err = ockam_vault_hkdf((uint8_t*)&g_protocol_salt,          /* Calculate HKDF using shared secret and pub keys    */
                            TEST_ATECC508A_PROTOCOL_SALT_SIZE,
                           (uint8_t* )&pms_static,
                            TEST_ATECC508A_PMS_SIZE,
                           &g_pub_key[0],
                           (TEST_ATECC508A_PUB_KEY_SIZE * TOTAL_TEST_ATECC508A_PUB_KEY),
                           &hkdf_key[0],
                            TEST_ATECC508A_HKDF_KEY_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault HKDF Failed\r\n");
        printf("Error Code: %08x\r\n", err);
    } else {
        printf("HKDF Key: \r\n");
        print_array(&hkdf_key[0], 16);
    }

    /* -------------------- */
    /* AES GCM Calculations */
    /* -------------------- */

    int ret;
    uint8_t aes_tag[TEST_ATECC508A_AES_TAG_SIZE];
    uint8_t aes_encrypt_hash[TEST_ATECC508A_AES_DATA_SIZE];
    uint8_t aes_decrypt_data[TEST_ATECC508A_AES_DATA_SIZE];

    err = ockam_vault_aes_gcm_encrypt(&g_aes_key[0],            /* Test the encrypt function using known values       */
                                       TEST_ATECC508A_AES_KEY_SIZE,
                                      &g_aes_iv[0],
                                       TEST_ATECC508A_AES_IV_SIZE,
                                      &g_aes_add[0],
                                       TEST_ATECC508A_AES_ADD_SIZE,
                                      &aes_tag[0],
                                       TEST_ATECC508A_AES_TAG_SIZE,
                                      &g_aes_plain_text[0],
                                       TEST_ATECC508A_AES_DATA_SIZE,
                                      &aes_encrypt_hash[0],
                                       TEST_ATECC508A_AES_DATA_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault AES GCM Encrypt Failed\r\n");
        printf("Error Code: %08x\r\n", err);
    }

    ret = memcmp(&aes_tag[0],                                   /* Compare the computed tag with the expected tag     */
                 &g_aes_tag[0],
                  TEST_ATECC508A_AES_TAG_SIZE);
    if(ret != 0) {
        printf("Error: AES GCM Tag calculated incorrectly\r\n");
    } else {
        printf("AES GCM Encrypt Tag Valid\r\n");
    }

    printf("Calculated Tag:\r\n");
    print_array(&aes_tag[0], 16);
    printf("Expected Tag:\r\n");
    print_array(&g_aes_tag[0], 16);

    ret = memcmp(&aes_encrypt_hash[0],                          /* Compare the computed hash with the expected hash   */
                 &g_aes_encrypt_hash[0],
                  TEST_ATECC508A_AES_DATA_SIZE);
    if(ret != 0) {
        printf("Error: AES GCM Tag calculated incorrectly\r\n");
    } else {
        printf("AES GCM Encrypt Hash Valid\r\n");
    }
    printf("Calculated Hash:\r\n");
    print_array(&aes_encrypt_hash[0], 60);
    printf("Expected Hash:\r\n");
    print_array(&g_aes_encrypt_hash[0], 60);

    err = ockam_vault_aes_gcm_decrypt(&g_aes_key[0],            /* Test the decrypt function using known values       */
                                       TEST_ATECC508A_AES_KEY_SIZE,
                                      &g_aes_iv[0],
                                       TEST_ATECC508A_AES_IV_SIZE,
                                      &g_aes_add[0],
                                       TEST_ATECC508A_AES_ADD_SIZE,
                                      &g_aes_tag[0],
                                       TEST_ATECC508A_AES_TAG_SIZE,
                                      &g_aes_encrypt_hash[0],
                                       TEST_ATECC508A_AES_DATA_SIZE,
                                      &aes_decrypt_data[0],
                                       TEST_ATECC508A_AES_DATA_SIZE);
    if(err != OCKAM_ERR_NONE) {
        printf("Error: Ockam Vault AES GCM Decrypt Failed\r\n");
        printf("Error Code: %08x\r\n", err);
    }

    ret = memcmp(&aes_decrypt_data,                             /* Compare the computed hash with the expected hash   */
                 &g_aes_plain_text,
                  TEST_ATECC508A_AES_DATA_SIZE);
    if(ret != 0) {
        printf("Error: AES GCM decrypt calculated incorrectly\r\n");
    } else {
        printf("AES GCM Decrypt Hash Valid\r\n");
    }

    printf("Decrypted Data: \r\n");
    print_array(&aes_decrypt_data[0], 60);
    printf("Expected Data: \r\n");
    print_array(&g_aes_plain_text[0], 60);

    return;
}


/**
 ********************************************************************************************************
 *                                          print_array()
 *
 * @brief   Handy function to print out array values in hex
 *
 * @param   p_array Array pointer to print
 *
 * @param   size    Size of the array to print
 *
 ********************************************************************************************************
 */

void print_array(uint8_t* p_array, uint32_t size)
{
	uint32_t i;

	for(i = 1; i <= size; i++) {
        printf("%02X ", *p_array);
        p_array++;
        if(i % 8 == 0) {
            printf("\r");
        }
    }
	printf("\r\n");
}

