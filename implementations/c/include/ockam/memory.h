/**
 ********************************************************************************************************
 * @file    memory.h
 * @brief   Generic memory functions for the Ockam Library
 ********************************************************************************************************
 */

#ifndef OCKAM_MEMORY_H_
#define OCKAM_MEMORY_H_


/*
 ********************************************************************************************************
 * @defgroup    OCKAM_MEMORY OCKAM_MEMORY_API
 * @ingroup     OCKAM
 * @brief       OCKAM_MEMORY_API
 *
 * @addtogroup  OCKAM_MEMORY
 * @{
 ********************************************************************************************************
 */


/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <ockam/define.h>


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

OCKAM_ERR ockam_mem_init(void* p_buf);

OCKAM_ERR ockam_mem_alloc(void** p_buf, uint32_t size);

OCKAM_ERR ockam_mem_free(void* p_buf);

OCKAM_ERR ockam_mem_copy(void* p_target, void* p_source, uint32_t length);


#ifdef __cplusplus
}
#endif

/*
 ********************************************************************************************************
 * @}
 ********************************************************************************************************
 */

#endif
