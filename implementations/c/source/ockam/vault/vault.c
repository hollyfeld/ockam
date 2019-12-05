/**
 ********************************************************************************************************
 * @file        vault.c
 * @brief
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <ockam/define.h>
#include <ockam/error.h>

#include <ockam/kal.h>
#include <ockam/vault.h>
#include <ockam/vault/tpm.h>
#include <ockam/vault/host.h>

#if !defined(OCKAM_VAULT_CONFIG_FILE)
#error "Error: Ockam Vault Config File Missing"
#else
#include OCKAM_VAULT_CONFIG_FILE
#endif


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

typedef enum {
    VAULT_STATE_UNINIT = 0x01,                                  /*!< Vault is uninitialized                           */
    VAULT_STATE_IDLE   = 0x02                                   /*!< Vault is in idle                                 */
} VAULT_STATE_e;


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

static OCKAM_KAL_MUTEX g_vault_mutex;

static VAULT_STATE_e g_vault_state = VAULT_STATE_UNINIT;


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


/**
 ********************************************************************************************************
 *                                          ockam_vault_init()
 *
 * @brief   Initialize the Ockam Vault
 *
 * @param   p_cfg   Configuration values for a TPM and/or a host software library
 *
 * @return  OCKAM_ERR_NONE if initialized successfully. OCKAM_ERR_VAULT_ALREADY_INIT if already
 *          initialized. Other errors if specific chip fails init.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_init(OCKAM_VAULT_CFG_s *p_cfg)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;


    do {
        if(g_vault_state != VAULT_STATE_UNINIT) {               /* Make sure we're not already initialized            */
            ret_val = OCKAM_ERR_VAULT_ALREADY_INIT;
            break;
        }

                                                                /* Create a mutex for vault access                    */
        ret_val = ockam_kal_mutex_init(&g_vault_mutex);
        if(ret_val != OCKAM_ERR_NONE) {
            break;
        }


#if(OCKAM_VAULT_CFG_INIT & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_init(p_cfg->p_tpm);           /* Initialize the TPM code if needed                  */
        if(ret_val != OCKAM_ERR_NONE) {
            break;
        }
#endif

#if(OCKAM_VAULT_CFG_INIT & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_init(p_cfg->p_host);         /* Initialize the host software lib code if needed    */

        if(ret_val != OCKAM_ERR_NONE) {                         /* If the software lib fails, free tpm if necessary   */
#if(OCKAM_VAULT_CFG_INIT & OCKAM_VAULT_CFG_TPM)
            ockam_vault_tpm_free();
#endif
            break;
        }
#endif

        g_vault_state = VAULT_STATE_IDLE;                       /* Set the vault state to idle so it can be used      */
    } while(0);

    if(ret_val != OCKAM_ERR_NONE) {                             /* If init fails, release any mutexes acquired        */
        ockam_kal_mutex_free(&g_vault_mutex);                   /*  No need to check return, free may fail if it was  */
    }                                                           /*  never acquired.                                   */

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                        ockam_vault_random()
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

OCKAM_ERR ockam_vault_random(uint8_t *p_rand_num, uint32_t rand_num_size)
{
    OCKAM_ERR ret_val;
    OCKAM_ERR t_ret_val;

    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state           */
        if(ret_val != OCKAM_ERR_NONE) {
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_RAND & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_random(p_rand_num,            /* Get a random number from the TPM                   */
                                         rand_num_size);
#elif(OCKAM_VAULT_CFG_RAND & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_random(p_rand_num,           /* Get a random number from the host library          */
                                          rand_num_size);
#else
#error "Ockam Vault: Random function not specified"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                          ockam_vault_key_gen()
 *
 * @brief   Generate an ECC keypair and get the public key
 *
 * @param   key_type[in]        The type of key pair to generate.
 *
 * @param   p_key_pub[out]      Buffer to place the public key in
 *
 * @param   key_pub_size[in]    The size of the key buffer
 *
 * @return  OCKAM_ERR_NONE if successful.
 *
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_key_gen(OCKAM_VAULT_KEY_e key_type, uint8_t *p_key_pub, uint32_t key_pub_size)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;
    OCKAM_ERR t_ret_val = OCKAM_ERR_NONE;


    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state or        */
        if(ret_val != OCKAM_ERR_NONE) {                         /* generating a key                                   */
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_key_gen(key_type,             /* Generate a key in the TPM                          */
                                         p_key_pub,
                                         key_pub_size);
#elif(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_key_gen(key_type,            /* Generate a key using the host library              */
                                             p_key_pub,
                                             key_pub_size);
#else
#error "Ockam Vault: Key Gen Function Missing"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                          ockam_vault_key_get_pub()
 *
 * @brief   Get a public key from the ATECC508A
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

OCKAM_ERR ockam_vault_key_get_pub(OCKAM_VAULT_KEY_e key_type, uint8_t *p_key_pub, uint32_t key_pub_size)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;
    OCKAM_ERR t_ret_val = OCKAM_ERR_NONE;


    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state or        */
        if(ret_val != OCKAM_ERR_NONE) {                         /* getting the public key                             */
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_key_get_pub(key_type,         /* Get a public key from the TPM                      */
                                              p_key_pub,
                                              key_pub_size);
#elif(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_key_get_pub(key_type,        /* Get a public key from the host library             */
                                               p_key_pub,
                                               key_pub_size);
#else
#error "Ockam Vault: Key Get Pub Function Missing"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                          ockam_vault_ecdh()
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

OCKAM_ERR ockam_vault_ecdh(OCKAM_VAULT_KEY_e key_type,
                           uint8_t *p_key_pub,
                           uint32_t key_pub_size,
                           uint8_t *p_pms,
                           uint32_t pms_size)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;
    OCKAM_ERR t_ret_val = OCKAM_ERR_NONE;


    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state or        */
        if(ret_val != OCKAM_ERR_NONE) {                         /* performing the ECDH operation                      */
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_ecdh(key_type,                 /* Perform an ECDH operation in a TPM                 */
                                       p_key_pub,
                                       key_pub_size,
                                       p_pms,
                                       pms_size);
#elif(OCKAM_VAULT_CFG_KEY_ECDH & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_ecdh(key_type,               /* Perform an ECDH operation in the host library      */
                                        p_key_pub,
                                        key_pub_size,
                                        p_pms,
                                        pms_size);
#else
#error "Ockam Vault: ECDH Function missing"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                          ockam_vault_hkdf()
 *
 * @brief   Perform HKDF operation on the input key material and optional salt and info. Place the
 *          result in the output buffer.
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

OCKAM_ERR ockam_vault_hkdf(uint8_t *p_salt,
                           uint32_t salt_size,
                           uint8_t *p_ikm,
                           uint32_t ikm_size,
                           uint8_t *p_info,
                           uint32_t info_size,
                           uint8_t *p_out,
                           uint32_t out_size)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;
    OCKAM_ERR t_ret_val = OCKAM_ERR_NONE;


    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state or        */
        if(ret_val != OCKAM_ERR_NONE) {                         /* performing the HKDF operation                      */
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_HKDF & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_hkdf(p_salt, salt_size,       /* Perform an HKDF operation in a TPM                 */
                                       p_ikm, ikm_size,
                                       p_info, info_size,
                                       p_out, out_size);
#elif(OCKAM_VAULT_CFG_HKDF & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_hkdf(p_salt, salt_size,        /* Perform an HKDF operation in the host library      */
                                        p_ikm, ikm_size,
                                        p_info, info_size,
                                        p_out, out_size);
#else
#error "Ockam Vault: HKDF Function missing"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}


/**
 ********************************************************************************************************
 *                                      ockam_vault_aes_gcm_encrypt()
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_aes_gcm_encrypt(uint8_t *p_key, uint32_t key_size,
                                      uint8_t *p_iv, uint32_t iv_size,
                                      uint8_t *p_add, uint32_t add_size,
                                      uint8_t *p_tag, uint32_t tag_size,
                                      uint8_t *p_input, uint32_t input_size,
                                      uint8_t *p_output, uint32_t output_size)
{
    return ockam_vault_aes_gcm(OCKAM_VAULT_AES_GCM_MODE_ENCRYPT,
                               p_key, key_size,
                               p_iv, iv_size,
                               p_add, add_size,
                               p_tag, tag_size,
                               p_input, input_size,
                               p_output, output_size);
}

/**
 ********************************************************************************************************
 *                                       ockam_vault_aes_gcm_decrypt()
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_aes_gcm_decrypt(uint8_t *p_key, uint32_t key_size,
                                      uint8_t *p_iv, uint32_t iv_size,
                                      uint8_t *p_add, uint32_t add_size,
                                      uint8_t *p_tag, uint32_t tag_size,
                                      uint8_t *p_input, uint32_t input_size,
                                      uint8_t *p_output, uint32_t output_size)
{
    return ockam_vault_aes_gcm(OCKAM_VAULT_AES_GCM_MODE_DECRYPT,
                               p_key, key_size,
                               p_iv, iv_size,
                               p_add, add_size,
                               p_tag, tag_size,
                               p_input, input_size,
                               p_output, output_size);
}


/**
 ********************************************************************************************************
 *                                          ockam_vault_aes_gcm()
 ********************************************************************************************************
 */

OCKAM_ERR ockam_vault_aes_gcm(OCKAM_VAULT_AES_GCM_MODE_e mode,
                              uint8_t *p_key, uint32_t key_size,
                              uint8_t *p_iv, uint32_t iv_size,
                              uint8_t *p_add, uint32_t add_size,
                              uint8_t *p_tag, uint32_t tag_size,
                              uint8_t *p_input, uint32_t input_size,
                              uint8_t *p_output, uint32_t output_size)
{
    OCKAM_ERR ret_val = OCKAM_ERR_NONE;
    OCKAM_ERR t_ret_val = OCKAM_ERR_NONE;


    do {
        ret_val = ockam_kal_mutex_lock(&g_vault_mutex, 0, 0);   /* Lock the mutex before checking the state or        */
        if(ret_val != OCKAM_ERR_NONE) {                         /* performing the AES GCM operation                   */
            break;
        }

        if(g_vault_state != VAULT_STATE_IDLE) {                 /* Ensure vault is in an idle state before continuing */
            ret_val = OCKAM_ERR_VAULT_UNINITIALIZED;
            break;
        }

#if(OCKAM_VAULT_CFG_AES_GCM & OCKAM_VAULT_CFG_TPM)
        ret_val = ockam_vault_tpm_aes_gcm(mode,                 /* Perform the AES GCM operation in the TPM           */
                                          p_key, key_size,
                                          p_iv, iv_size,
                                          p_add, add_size,
                                          p_tag, tag_size,
                                          p_input, input_size,
                                          p_output, output_size);
#elif(OCKAM_VAULT_CFG_AES_GCM & OCKAM_VAULT_CFG_HOST)
        ret_val = ockam_vault_host_aes_gcm(mode,                /* Perform the AES GCM operation in on the host       */
                                           p_key, key_size,
                                           p_iv, iv_size,
                                           p_add, add_size,
                                           p_tag, tag_size,
                                           p_input, input_size,
                                           p_output, output_size);
#else
#error "Ockam Vault: AES GCM Function missing"
#endif
    } while(0);

    t_ret_val = ockam_kal_mutex_unlock(&g_vault_mutex, 0);      /* Unlock the mutex after all vault operations finish */
    if(ret_val == OCKAM_ERR_NONE) {                             /* Don't overwrite ret_val if there was an error      */
        ret_val = t_ret_val;                                    /* before the mutex unlock                            */
    }

    return ret_val;
}



