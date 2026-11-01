# Support both upstream packages and distributions without CMake exports.
find_path(MbedTLS_INCLUDE_DIR NAMES mbedtls/version.h)
if(MbedTLS_INCLUDE_DIR)
    foreach(header build_info.h version.h)
        if(EXISTS "${MbedTLS_INCLUDE_DIR}/mbedtls/${header}")
            file(STRINGS "${MbedTLS_INCLUDE_DIR}/mbedtls/${header}" version_line
                REGEX "^#define MBEDTLS_VERSION_STRING +\"")
            if(version_line)
                string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" MbedTLS_VERSION "${version_line}")
                break()
            endif()
        endif()
    endforeach()
endif()

function(apple_auth_find_mbedtls_config)
    # Upstream's SameMajorVersion check needs separate 2.x and 3.x requests.
    find_package(MbedTLS 3 CONFIG QUIET)
    if(NOT TARGET MbedTLS::mbedcrypto)
        find_package(MbedTLS 2.28 CONFIG QUIET)
    endif()
endfunction()
apple_auth_find_mbedtls_config()
set(MbedTLS_LIBRARIES_FOUND FALSE)
if(TARGET MbedTLS::mbedcrypto AND TARGET MbedTLS::mbedx509)
    set(MbedTLS_LIBRARIES_FOUND TRUE)
else()
    find_library(MbedTLS_CRYPTO_LIBRARY NAMES mbedcrypto)
    find_library(MbedTLS_X509_LIBRARY NAMES mbedx509)
    if(MbedTLS_CRYPTO_LIBRARY AND MbedTLS_X509_LIBRARY)
        set(MbedTLS_LIBRARIES_FOUND TRUE)
    endif()
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
    REQUIRED_VARS MbedTLS_INCLUDE_DIR MbedTLS_LIBRARIES_FOUND
    VERSION_VAR MbedTLS_VERSION)
if(MbedTLS_FOUND AND MbedTLS_VERSION VERSION_GREATER_EQUAL 4)
    message(FATAL_ERROR "Mbed TLS 4 is unsupported; use Mbed TLS 2.28 or 3.6 (Homebrew: mbedtls@3)")
endif()
if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedcrypto)
    add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
        IMPORTED_LOCATION "${MbedTLS_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}")
    if(WIN32)
        set_property(TARGET MbedTLS::mbedcrypto PROPERTY INTERFACE_LINK_LIBRARIES "ws2_32;bcrypt")
    endif()
    add_library(MbedTLS::mbedx509 UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedx509 PROPERTIES
        IMPORTED_LOCATION "${MbedTLS_X509_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES MbedTLS::mbedcrypto)
endif()
mark_as_advanced(MbedTLS_INCLUDE_DIR MbedTLS_CRYPTO_LIBRARY MbedTLS_X509_LIBRARY)
