/**
 ********************************************************************************************************
 * @file    tpm.h
 * @brief   Ockam Vault TPM Interface
 ********************************************************************************************************
 */

#ifndef OCKAM_VAULT_TPM_H_
#define OCKAM_VAULT_TPM_H_


/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <ockam/define.h>
#include <ockam/error.h>


/*
 ********************************************************************************************************
 *                                                DEFINES                                               *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                               CONSTANTS                                              *
 ********************************************************************************************************
 */

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

/*
 ********************************************************************************************************
 *                                           GLOBAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                            LOCAL FUNCTIONS                                           *
 ********************************************************************************************************
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 ********************************************************************************************************
 *                                         ockam_vault_tpm_init()
 *
 * @brief   Initialize the TPM for Ockam Vault
 *
 * @param   p_arg   Optional void* argument
 *
 * @return  OCKAM_ERR_NONE if initialized successfully. OCKAM_ERR_VAULT_ALREADY_INIT if already
 *          initialized. Other errors if specific chip fails init.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_init(void *p_arg);


/**
 ********************************************************************************************************
 *                                          ockam_vault_tpm_free()
 *
 * @brief   Free the TPM and all associated data structures
 *
 * @return  OCKAM_ERR_NONE on success.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_free(void);


/**
 ********************************************************************************************************
 *                                        ockam_vault_tpm_random()
 *
 * @brief   Generate and return a random number
 *
 * @param   p_rand_num[out]     32-byte array to be filled with the random number
 *
 * @param   rand_num_size[in]   The size of the desired random number & buffer passed in. Used to verify
 *                              correct size.
 *
 * @return  OCKAM_ERR_NONE if successful. OCKAM_ERR_VAULT_INVALID_SIZE if size
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_random(uint8_t *p_rand_num,
                                 uint32_t rand_num_size);


/**
 ********************************************************************************************************
 *                                        ockam_vault_tpm_key_gen()
 *
 * @brief   Generate an keypair of a specified type
 *
 * @param   key_type[in]    The type of key pair to generate.
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_key_gen(OCKAM_VAULT_KEY_e key_type,
                                  uint8_t *p_pub_key,
                                  uint32_t pub_key_size);

/**
 ********************************************************************************************************
 *                                        ockam_vault_tpm_key_get_pub()
 *
 * @brief   Get a public key from the TPM
 *
 * @param   key_type[in]        OCKAM_VAULT_KEY_STATIC if requesting static public key
 *                              OCKAM_VAULT_KEY_EPHEMERAL if requesting the ephemeral public key
 *
 * @param   p_pub_key[out]      Buffer to place the public key in
 *
 * @param   pub_key_size[in]    Size of the public key buffer
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_key_get_pub(OCKAM_VAULT_KEY_e key_type,
                                      uint8_t *p_pub_key,
                                      uint32_t pub_key_size);


/**
 ********************************************************************************************************
 *                                        ockam_vault_tpm_ecdh()
 *
 * @brief   Perform ECDH using the specified key
 *
 * @param   key_type[in]        Specify which key type to use in the ECDH execution
 *
 * @param   p_pub_key[in]       Buffer with the public key
 *
 * @param   pub_key_size[in]    Size of the public key buffer
 *
 * @param   p_pms[out]          Pre-master secret from ECDH
 *
 * @param   pms_size[in]        Size of the pre-master secret buffer
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_ecdh(OCKAM_VAULT_KEY_e key_type,
                               uint8_t *p_pub_key,
                               uint32_t pub_key_size,
                               uint8_t *p_pms,
                               uint32_t pms_size);

/**
 ********************************************************************************************************
 *                                       ockam_vault_tpm_hkdf()
 *
 * @brief   Perform HKDF in the TPM
 *
 * @param   p_salt[in]          Buffer for the Ockam salt value
 *
 * @param   salt_size[in]       Size of the Ockam salt value
 *
 * @param   p_ikm[in]           Buffer with the input key material for HKDF
 *
 * @param   ikm_size[in]        Size of the input key material
 *
 * @param   p_info[in]          Buffer with the optional context specific info. Can be 0.
 *
 * @param   info_size[in]       Size of the optional context specific info.
 *
 * @param   p_out[out]          Buffer for the output of the HKDF operation
 *
 * @param   out_size[in]        Size of the HKDF output buffer
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_hkdf(uint8_t *p_salt, uint32_t salt_size,
                               uint8_t *p_ikm, uint32_t ikm_size,
                               uint8_t *p_info, uint32_t info_size,
                               uint8_t *p_out, uint32_t out_size);

/**
 ********************************************************************************************************
 *                                          ockam_vault_tpm_aes_gcm()
 *
 * @brief   Perform AES GCM in the mbed TLS library
 *
 * @param   mode                AES GCM Mode: Encrypt or Decrypt
 *
 * @param   p_key[in]           Buffer for the AES Key
 *
 * @param   key_size[in]        Size of the AES Key. Must be 128, 192 or 256 bits
 *
 * @param   p_iv[in]            Buffer with the initialization vector
 *
 * @param   iv_size[in]         Size of the initialization vector
 *
 * @param   p_add[in]           Buffer with the additional data (can be NULL)
 *
 * @param   add_size[in]        Size of the additional data (set to 0 if p_add is NULL)
 *
 * @param   p_tag[in,out]       Buffer to either hold the tag when encrypting or pass in the tag
 *                              when decrypting.
 *
 * @param   tag_size[in]        Size of the tag buffer
 *
 * @param   p_input[in]         Buffer with the input data to encrypt or decrypt
 *
 * @param   input_size[in]      Size of the input data
 *
 * @param   p_output[out]       Buffer for the output of the AES GCM operation. Can NOT be the
 *                              input buffer.
 *
 * @param   output_size[in]     Size of the output buffer
 *
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_tpm_aes_gcm(OCKAM_VAULT_AES_GCM_MODE_e mode,
                                  uint8_t *p_key, uint32_t key_size,
                                  uint8_t *p_iv, uint32_t iv_size,
                                  uint8_t *p_add, uint32_t add_size,
                                  uint8_t *p_tag, uint32_t tag_size,
                                  uint8_t *p_input, uint32_t input_size,
                                  uint8_t *p_output, uint32_t output_size);

#ifdef __cplusplus
}
#endif

#endif
