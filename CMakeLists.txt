cmake_minimum_required(VERSION 3.24)
option(APPLE_AUTH_WITH_TESTFLIGHT "Build independent TestFlight catalog and encrypted IPA download" OFF)
if(APPLE_AUTH_WITH_TESTFLIGHT)
    list(APPEND VCPKG_MANIFEST_FEATURES client testflight)
    list(REMOVE_DUPLICATES VCPKG_MANIFEST_FEATURES)
endif()
project(apple_auth VERSION 0.1.3 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(GenerateExportHeader)
include(CMakeDependentOption)

set(apple_auth_desktop ON)
if(CMAKE_SYSTEM_NAME MATCHES "^(iOS|tvOS|watchOS|visionOS)$")
    set(apple_auth_desktop OFF)
endif()
option(BUILD_SHARED_LIBS "Build shared libraries" ${apple_auth_desktop})
option(APPLE_AUTH_WITH_CLIENT "Build HTTP provisioning, GrandSlam and Store login" ON)
option(APPLE_AUTH_WITH_CURL "Provide the built-in curl HTTPS transport" ${apple_auth_desktop})
if(APPLE_AUTH_WITH_TESTFLIGHT AND (NOT APPLE_AUTH_WITH_CLIENT OR NOT APPLE_AUTH_WITH_CURL))
    message(FATAL_ERROR "TestFlight downloads require APPLE_AUTH_WITH_CLIENT and APPLE_AUTH_WITH_CURL")
endif()
cmake_dependent_option(APPLE_AUTH_BUILD_EXAMPLES "Build integration examples" ON
    "PROJECT_IS_TOP_LEVEL;apple_auth_desktop" OFF)
option(APPLE_AUTH_SANITIZERS "Enable address and undefined-behavior sanitizers" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(MbedTLS 2.28 REQUIRED)

add_library(apple_auth
    src/adi/core.cpp
    src/adi/key_derivation.cpp
    src/adi/file_key/mutation.cpp
    src/adi/state.cpp
    src/adi/otp.cpp
    src/adi/mac.cpp
    src/adi/android.cpp
    src/adi/parameters.cpp
    src/adi/provisioning.cpp
    src/adi/provisioning/mixer.cpp
    src/adi/provisioning/seed.cpp
    src/api/c_api.cpp
    src/crypto/crypto.cpp
    src/crypto/session_crypto.cpp
    src/crypto/srp.cpp
    src/sap/session.cpp
    src/sap/certificate.cpp)
add_library(apple_auth::core ALIAS apple_auth)
set_target_properties(apple_auth PROPERTIES EXPORT_NAME core VERSION ${PROJECT_VERSION} SOVERSION 0
    CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES)
target_compile_features(apple_auth PUBLIC cxx_std_20)
target_include_directories(apple_auth PRIVATE src)
target_include_directories(apple_auth PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(apple_auth PRIVATE MbedTLS::mbedcrypto MbedTLS::mbedx509)
if(BUILD_SHARED_LIBS AND UNIX AND NOT APPLE)
    target_link_options(apple_auth PRIVATE "LINKER:--exclude-libs,ALL")
endif()
generate_export_header(apple_auth BASE_NAME APPLE_AUTH EXPORT_FILE_NAME include/apple_auth/export.h)
if(NOT BUILD_SHARED_LIBS)
    target_compile_definitions(apple_auth PUBLIC APPLE_AUTH_STATIC_DEFINE)
endif()
if(WIN32)
    target_link_libraries(apple_auth PRIVATE advapi32)
endif()

function(apple_auth_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /utf-8 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        if(APPLE_AUTH_SANITIZERS)
            target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()
function(apple_auth_runtime target)
    if(WIN32 AND BUILD_SHARED_LIBS)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} "-DDLLS=$<TARGET_RUNTIME_DLLS:${target}>"
                "-DDESTINATION=$<TARGET_FILE_DIR:${target}>"
                -P "${PROJECT_SOURCE_DIR}/cmake/CopyRuntime.cmake")
    endif()
endfunction()
apple_auth_warnings(apple_auth)
apple_auth_runtime(apple_auth)
if(APPLE_AUTH_SANITIZERS)
    if(MSVC)
        message(FATAL_ERROR "APPLE_AUTH_SANITIZERS currently requires GCC or Clang on Unix")
    endif()
    target_link_options(apple_auth INTERFACE -fsanitize=address,undefined)
endif()

set(apple_auth_install_targets apple_auth)
if(APPLE_AUTH_WITH_TESTFLIGHT)
    target_sources(apple_auth PRIVATE src/store/core.cpp)
endif()
if(APPLE_AUTH_WITH_CLIENT)
    if(APPLE_AUTH_WITH_CURL)
        find_package(CURL 7.85 REQUIRED)
        set(apple_auth_http_library CURL::libcurl)
        set(apple_auth_transport src/client/transport.cpp)
    else()
        set(apple_auth_transport src/client/external_transport.cpp)
    endif()
    find_package(nlohmann_json 3.10 REQUIRED)
    if(APPLE)
        set(apple_auth_plist "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
        set(apple_auth_plist_source src/client/apple_plist.cpp)
    elseif(WIN32)
        find_package(unofficial-libplist CONFIG REQUIRED)
        set(apple_auth_plist unofficial::libplist::libplist)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(PLIST REQUIRED IMPORTED_TARGET libplist-2.0>=2.3)
        set(apple_auth_plist PkgConfig::PLIST)
    endif()
    if(NOT APPLE)
        include(CMakePushCheckState)
        include(CheckSymbolExists)
        cmake_push_check_state(RESET)
        set(CMAKE_REQUIRED_LIBRARIES ${apple_auth_plist})
        check_symbol_exists(plist_get_unix_date_val "plist/plist.h" APPLE_AUTH_PLIST_UNIX_DATE)
        cmake_pop_check_state()
    endif()
    add_library(apple_auth_client
        src/api/client_api.cpp
        src/client/client.cpp
        src/client/client_support.cpp
        src/client/session_storage.cpp
        src/client/state_storage.cpp
        ${apple_auth_transport}
        ${apple_auth_plist_source}
        src/client/authentication.cpp
        src/client/store.cpp)
    target_include_directories(apple_auth_client PRIVATE src)
    add_library(apple_auth::client ALIAS apple_auth_client)
    set_target_properties(apple_auth_client PROPERTIES EXPORT_NAME client VERSION ${PROJECT_VERSION} SOVERSION 0
        CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES)
    target_link_libraries(apple_auth_client PUBLIC apple_auth PRIVATE MbedTLS::mbedcrypto
        ${apple_auth_http_library} nlohmann_json::nlohmann_json ${apple_auth_plist})
    if(APPLE_AUTH_WITH_CURL)
        target_compile_definitions(apple_auth_client PRIVATE APPLE_AUTH_WITH_CURL)
    endif()
    if(WIN32)
        target_link_libraries(apple_auth_client PRIVATE advapi32 crypt32)
    endif()
    if(APPLE_AUTH_PLIST_UNIX_DATE)
        target_compile_definitions(apple_auth_client PRIVATE APPLE_AUTH_PLIST_UNIX_DATE)
    endif()
    if(APPLE)
        set_target_properties(apple_auth_client PROPERTIES INSTALL_RPATH "@loader_path")
    elseif(UNIX)
        set_target_properties(apple_auth_client PROPERTIES INSTALL_RPATH "$ORIGIN")
        if(BUILD_SHARED_LIBS)
            target_link_options(apple_auth_client PRIVATE "LINKER:--exclude-libs,ALL")
        endif()
    endif()
    generate_export_header(apple_auth_client BASE_NAME APPLE_AUTH_CLIENT EXPORT_FILE_NAME include/apple_auth/client_export.h)
    if(NOT BUILD_SHARED_LIBS)
        target_compile_definitions(apple_auth_client PUBLIC APPLE_AUTH_CLIENT_STATIC_DEFINE)
    endif()
    apple_auth_runtime(apple_auth_client)
    apple_auth_warnings(apple_auth_client)
    list(APPEND apple_auth_install_targets apple_auth_client)
endif()

if(APPLE_AUTH_WITH_TESTFLIGHT)
    find_package(ZLIB REQUIRED)
    target_compile_definitions(apple_auth_client PRIVATE APPLE_AUTH_WITH_TESTFLIGHT)
    if(WIN32)
        find_package(libzip CONFIG REQUIRED)
        set(apple_auth_zip libzip::zip)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(TF_ZIP REQUIRED IMPORTED_TARGET libzip)
        set(apple_auth_zip PkgConfig::TF_ZIP)
    endif()
    include(FetchContent)
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    set(LZFSE_BUNDLE_MODE ON CACHE BOOL "Bundle pinned LZFSE" FORCE)
    FetchContent_Declare(lzfse GIT_REPOSITORY https://github.com/lzfse/lzfse.git
        GIT_TAG e634ca58b4821d9f3d560cdc6df5dec02ffc93fd)
    FetchContent_MakeAvailable(lzfse)
    target_sources(apple_auth_client PRIVATE
        src/client/download.cpp
        src/archive/ipa.cpp
        src/archive/macho.cpp
        src/appstore/client.cpp
        src/appstore/mac_package.cpp
        src/testflight/api.cpp
        src/testflight/protocol.cpp
        src/testflight/transport_file.cpp)
    target_include_directories(apple_auth_client PRIVATE ${lzfse_SOURCE_DIR}/src)
    target_link_libraries(apple_auth_client PRIVATE ${apple_auth_zip} ZLIB::ZLIB lzfse)
    list(APPEND apple_auth_install_targets lzfse)
endif()

if(APPLE_AUTH_BUILD_EXAMPLES)
    add_executable(apple_auth_otp examples/otp.cpp)
    target_link_libraries(apple_auth_otp PRIVATE apple_auth::core)
    apple_auth_runtime(apple_auth_otp)
    install(TARGETS apple_auth_otp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    if(APPLE_AUTH_WITH_CLIENT)
        add_executable(apple_auth_cli examples/client.cpp)
        set_target_properties(apple_auth_cli PROPERTIES OUTPUT_NAME apple-auth)
        target_link_libraries(apple_auth_cli PRIVATE apple_auth::client)
        apple_auth_runtime(apple_auth_cli)
        install(TARGETS apple_auth_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(apple_auth_store examples/store.cpp)
        set_target_properties(apple_auth_store PROPERTIES OUTPUT_NAME apple-auth-store)
        target_link_libraries(apple_auth_store PRIVATE apple_auth::client nlohmann_json::nlohmann_json)
        apple_auth_warnings(apple_auth_store)
        apple_auth_runtime(apple_auth_store)
        install(TARGETS apple_auth_store RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
    if(APPLE_AUTH_WITH_TESTFLIGHT)
        add_executable(apple_auth_testflight examples/testflight.cpp)
        set_target_properties(apple_auth_testflight PROPERTIES OUTPUT_NAME apple-auth-testflight)
        target_link_libraries(apple_auth_testflight PRIVATE apple_auth::client nlohmann_json::nlohmann_json)
        apple_auth_warnings(apple_auth_testflight)
        apple_auth_runtime(apple_auth_testflight)
        install(TARGETS apple_auth_testflight RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
        add_executable(apple_auth_appstore examples/appstore.cpp)
        set_target_properties(apple_auth_appstore PROPERTIES OUTPUT_NAME apple-auth-appstore)
        target_link_libraries(apple_auth_appstore PRIVATE apple_auth::client)
        apple_auth_warnings(apple_auth_appstore)
        apple_auth_runtime(apple_auth_appstore)
        install(TARGETS apple_auth_appstore RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
    if(APPLE)
        set(apple_auth_example_rpath "@loader_path/../${CMAKE_INSTALL_LIBDIR}")
    elseif(UNIX)
        set(apple_auth_example_rpath "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
    endif()
    if(apple_auth_example_rpath)
        set_target_properties(apple_auth_otp PROPERTIES INSTALL_RPATH "${apple_auth_example_rpath}")
        if(TARGET apple_auth_cli)
            set_target_properties(apple_auth_cli PROPERTIES INSTALL_RPATH "${apple_auth_example_rpath}")
            set_target_properties(apple_auth_store PROPERTIES INSTALL_RPATH "${apple_auth_example_rpath}")
        endif()
        if(TARGET apple_auth_testflight)
            set_target_properties(apple_auth_testflight PROPERTIES INSTALL_RPATH "${apple_auth_example_rpath}")
            set_target_properties(apple_auth_appstore PROPERTIES INSTALL_RPATH "${apple_auth_example_rpath}")
        endif()
    endif()
endif()

install(TARGETS ${apple_auth_install_targets} EXPORT apple_authTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/apple_auth/core.hpp include/apple_auth/c_api.h include/apple_auth/srp.hpp
    include/apple_auth/session_crypto.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/include/apple_auth/export.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/apple_auth)
if(APPLE_AUTH_WITH_CLIENT)
    install(FILES include/apple_auth/client.hpp include/apple_auth/client_c_api.h ${CMAKE_CURRENT_BINARY_DIR}/include/apple_auth/client_export.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/apple_auth)
    install(DIRECTORY python/apple_auth DESTINATION ${CMAKE_INSTALL_DATADIR}/apple_auth/python
        PATTERN "__pycache__" EXCLUDE)
    install(PROGRAMS examples/login.py examples/device_login.py examples/async_device_login.py
        examples/store_login.py examples/async_store_login.py
        DESTINATION ${CMAKE_INSTALL_DATADIR}/apple_auth/examples)
endif()
if(APPLE_AUTH_WITH_TESTFLIGHT)
    install(FILES include/apple_auth/store_core.hpp include/apple_auth/testflight_core.hpp
        include/apple_auth/testflight.hpp include/apple_auth/appstore.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/apple_auth)
    install(FILES ${lzfse_SOURCE_DIR}/LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/apple_auth/licenses RENAME LZFSE.txt)
endif()
configure_package_config_file(cmake/apple_authConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/apple_authConfig.cmake INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/apple_auth)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/apple_authConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(EXPORT apple_authTargets NAMESPACE apple_auth:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/apple_auth)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/apple_authConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/apple_authConfigVersion.cmake DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/apple_auth)
install(FILES cmake/FindMbedTLS.cmake DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/apple_auth)
install(FILES LICENSE THIRD_PARTY_NOTICES.md DESTINATION ${CMAKE_INSTALL_DATADIR}/apple_auth)
install(DIRECTORY LICENSES/ DESTINATION ${CMAKE_INSTALL_DATADIR}/apple_auth/licenses)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs DESTINATION ${CMAKE_INSTALL_DOCDIR})
