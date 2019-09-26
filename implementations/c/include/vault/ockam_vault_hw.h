/**
 ********************************************************************************************************
 * @file        ockam_vault_hw.h
 * @author      Mark Mulrooney <mark@ockam.io>
 * @copyright   Copyright (c) 2019, Ockam Inc.
 * @brief   
 ********************************************************************************************************
 */

#ifndef OCKAM_VAULT_HW_H_
#define OCKAM_VAULT_HW_H_


/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <ockam_def.h>
#include <ockam_err.h>


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


OCKAM_ERR ockam_vault_hw_init(void *p_arg);

OCKAM_ERR ockam_vault_hw_free(void);

OCKAM_ERR ockam_vault_hw_random(uint8_t *p_rand_num,
                                uint32_t rand_num_size);

OCKAM_ERR ockam_vault_hw_key_gen(OCKAM_VAULT_KEY_e key_type,
                                 uint8_t *p_pub_key,
                                 uint32_t pub_key_size);

OCKAM_ERR ockam_vault_hw_key_get_pub(OCKAM_VAULT_KEY_e key_type,
                                     uint8_t *p_pub_key,
                                     uint32_t pub_key_size);

OCKAM_ERR ockam_vault_hw_ecdh(OCKAM_VAULT_KEY_e key_type,
                              uint8_t *p_pub_key,
                              uint32_t pub_key_size,
                              uint8_t *p_pms,
                              uint32_t pms_size);

OCKAM_ERR ockam_vault_hw_hkdf(uint8_t *p_salt,
                              uint32_t salt_size,
                              uint8_t *p_ikm,
                              uint32_t ikm_size,
                              uint8_t *p_info,
                              uint32_t info_size,
                              uint8_t *p_out,
                              uint32_t out_size);
#ifdef __cplusplus
}
#endif

#endif
