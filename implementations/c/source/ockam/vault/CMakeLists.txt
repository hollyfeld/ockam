cmake_minimum_required(VERSION 3.13)
project(ockam_vault)

# Clear the Vault vars 
set(VAULT_INC)
set(VAULT_SRC)
set(CMAKE_VERBOSE_MAKEFILE TRUE)


#######################
# Directory Locations #
#######################

set(VAULT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(VAULT_HW_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hardware)
set(VAULT_SW_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/software)

set(OCKAM_INC_DIR ${OCKAM_C_BASE}/include)
set(THIRD_PARTY_DIR ${OCKAM_C_BASE}/third-party/)


#################
# Build Options #
#################

# Vault Hardware Build Options
option(VAULT_HW_ATECC508A "Vault Hardware: Microchip ATECC508A")
option(VAULT_HW_ATECC608A "Vault Hardware: Microchip ATECC608A")

# Vault Software Build Options
option(VAULT_SW_MBEDTLS "Vault Software: mbed TLS")
option(VAULT_SW_MBEDCRYPTO "Vault Software: mbed Crypto")
option(VAULT_SW_LIBSODIUM "Vault Software: Lib Sodium")

# Vault Interface Options
option(VAULT_IFACE_I2C "Vault IFace: I2C")
option(VAULT_IFACE_SPI "Vault IFace: SPI")
option(VAULT_IFACE_UART "Vault IFace: UART")


###################
# Vault Interface #
###################

set(VAULT_SRC ${VAULT_SRC_DIR}/vault.c)
set(VAULT_INC ${OCKAM_INC_DIR})


####################
# HW Specific Code #
####################

# ATECC508A Specific Config 
if(VAULT_HW_ATECC508A)
    set(VAULT_SRC ${VAULT_SRC} ${VAULT_HW_SRC_DIR}/microchip/atecc508a.c)
    set(VAULT_HW_VENDOR_MICROCHIP TRUE)
endif()

# ATECC608A Specific Config 
if(VAULT_HW_ATECC608A)
    set(VAULT_SRC ${VAULT_SRC} ${VAULT_HW_SRC_DIR}/microchip/atecc608a.c)
    set(VAULT_HW_VENDOR_MICROCHIP TRUE)
endif()


####################
# SW Specific Code #
####################

# mbedTLS Specific Config
if(VAULT_SW_MBEDTLS)
    set(VAULT_SRC ${VAULT_SRC} ${VAULT_SW_SRC_DIR}/mbedtls.c)
endif()

# mbed Crypto Specific Config
if(VAULT_SW_MBEDCRYPTO)
    set(VAULT_SRC ${VAULT_SRC} ${VAULT_SW_SRC_DIR}/mbedcrypto.c)
endif()

# LibSodiumSpecific Config
if(VAULT_SW_LIBSODIUM)
    set(VAULT_SRC ${VAULT_SRC} ${VAULT_SW_SRC_DIR}/libsodium.c)
endif()


########################
# Vendor Specific Code #
########################

# For Microchip Hardware, add cryptoauthlib
if(VAULT_HW_VENDOR_MICROCHIP)
    set(VAULT_INC ${VAULT_INC} ${VAULT_HW_SRC_DIR}/microchip/)
    set(VAULT_INC ${VAULT_INC} ${THIRD_PARTY_DIR}/microchip/)
    set(VAULT_INC ${VAULT_INC} ${THIRD_PARTY_DIR}/microchip/cryptoauthlib/lib)
    set(VAULT_INC ${VAULT_INC} ${THIRD_PARTY_DIR}/microchip/cryptoauthlib/lib/hal)

    if(VAULT_IFACE_I2C)
        set(ATCA_HAL_I2C ON CACHE BOOL "")
        set(ATCA_BUILD_SHARED_LIBS OFF CACHE BOOL "")
    endif()
    add_subdirectory(${THIRD_PARTY_DIR}/microchip/cryptoauthlib cryptoauthlib)
endif()

# For mbed TLS, add the library
if(VAULT_SW_MBEDTLS)
    set(VAULT_INC ${VAULT_INC} ${THIRD_PARTY_DIR}/arm/mbedtls/include)

    set(ENABLE_TESTING OFF CACHE BOOL "")
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    add_subdirectory(${THIRD_PARTY_DIR}/arm/mbedtls mbedtls)
endif()

# For mbed Crypto, add the library
if(VAULT_SW_MBEDCRYPTO)
    set(VAULT_INC ${VAULT_INC} ${THIRD_PARTY_DIR}/arm/mbed-crypto/include)

    set(ENABLE_TESTING OFF CACHE BOOL "")
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    add_subdirectory(${THIRD_PARTY_DIR}/arm/mbed-crypto mbed-crypto)
endif()

####################
# Interface Option #
####################

if(VAULT_IFACE_I2C)
    add_definitions(-DVAULT_IFACE_I2C)
endif()

if(VAULT_IFACE_SPI)
    add_definitions(-DVAULT_IFACE_SPI)
endif()

if(VAULT_IFACE_UART)
    add_definitions(-DVAULT_IFACE_UART)
endif()


###################
# Generate Build! #
###################

# Add the source files
add_library(ockam_vault ${VAULT_SRC})

# Set the include directories
target_include_directories(ockam_vault PUBLIC ${VAULT_INC})

# Set the target
set_property(TARGET ockam_vault PROPERTY C_STANDARD 99)
