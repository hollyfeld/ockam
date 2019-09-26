/**
 ********************************************************************************************************
 * @file        ockam_kal.h
 * @author      Mark Mulrooney <mark@ockam.io>
 * @copyright   Copyright (c) 2019, Ockam Inc.
 * @brief   
 ********************************************************************************************************
 */

#ifndef OCKAM_KAL_H_
#define OCKAM_KAL_H_


/*
 ********************************************************************************************************
 * @defgroup    OCKAM_KAL OCKAM_KAL_API
 * @ingroup     OCKAM
 * @brief       OCKAM_KAL_API
 *
 * @addtogroup  OCKAM_KAL
 * @{
 ********************************************************************************************************
 */

/*
 ********************************************************************************************************
 *                                             INCLUDE FILES                                            *
 ********************************************************************************************************
 */

#include <stdlib.h>
#include <stdint.h>

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


/**
 *******************************************************************************
 * @enum    OCKAM_KAL_OPT
 * @brief   Options when making OS calls
 *******************************************************************************
 */

typedef enum {
    OCKAM_KAL_OPT_NONE              = 0x00,                     /*!< No option specified                                */
    OCKAM_KAL_OPT_BLOCKING          = 0x00,                     /*!< Make a blocking call (default)                     */
    OCKAM_KAL_OPT_NON_BLOCKING      = 0x01,                     /*!< Make a non-blocking call, if applicable            */
    OCKAM_KAL_OPT_NO_SCHED          = 0x02,                     /*!< Don't run the scheduler, if applicable             */
} OCKAM_KAL_OPT;


/*
 ********************************************************************************************************
 *                                               DATA TYPES                                             *
 ********************************************************************************************************
 */


/**
 *******************************************************************************
 * @struct  OCKAM_KAL_MUTEX
 * @brief   Kernel abstraction layer for mutex
 *******************************************************************************
 */

typedef struct {
    void *mutex_ptr;                                            /*!< Void* for the mutex                                */
} OCKAM_KAL_MUTEX;


/**
 *******************************************************************************
 * @struct  OCKAM_KAL_QUEUE
 * @brief   Kernel abstraction layer for queue
 *******************************************************************************
 */

typedef struct {
    void *queue_ptr;                                            /*!< Void* for the queue                                */
} OCKAM_KAL_QUEUE;


/*
 ********************************************************************************************************
 ********************************************************************************************************
 *                                            KAL FUNCTIONS                                             *
 ********************************************************************************************************
 ********************************************************************************************************
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 ********************************************************************************************************
 *                                               MUTEX                                                  *
 ********************************************************************************************************
 */

OCKAM_ERR  ockam_kal_mutex_init (OCKAM_KAL_MUTEX *p_mutex);

OCKAM_ERR  ockam_kal_mutex_free (OCKAM_KAL_MUTEX *p_mutex);

OCKAM_ERR  ockam_kal_mutex_lock (OCKAM_KAL_MUTEX *p_mutex,
                                   OCKAM_KAL_OPT opt, 
                                   uint32_t timeout_ms);

OCKAM_ERR  ockam_kal_mutex_unlock (OCKAM_KAL_MUTEX *p_mutex,
                                  OCKAM_KAL_OPT opt);


/*
 ********************************************************************************************************
 *                                              QUEUE                                                   *
 ********************************************************************************************************
 */

OCKAM_ERR  ockam_kal_queue_init (OCKAM_KAL_QUEUE *p_queue,
                                 uint32_t queue_size);

OCKAM_ERR  ockam_kal_queue_free (OCKAM_KAL_QUEUE *p_queue);

OCKAM_ERR  ockam_kal_queue_pop (OCKAM_KAL_QUEUE *p_queue,
                                OCKAM_KAL_OPT opt, 
                                uint32_t timeout_ms);

OCKAM_ERR  ockam_kal_queue_push (OCKAM_KAL_QUEUE *p_queue,
                                 OCKAM_KAL_OPT opt);

#ifdef __cplusplus
}
#endif

/*
 ********************************************************************************************************
 * @}
 ********************************************************************************************************
 */

#endif
