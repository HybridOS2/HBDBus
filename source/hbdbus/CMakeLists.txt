include(GlobalCommon)

configure_file(include/hbdbus-version.h.in ${FORWARDING_HEADERS_DIR}/hbdbus/hbdbus-version.h @ONLY)

set(HBDBus_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDBUS_DIR}"
    "${HBDBUS_DIR}/include"
    "${HBDBus_DERIVED_SOURCES_DIR}"
    "${FORWARDING_HEADERS_DIR}/hbdbus"
)

list(APPEND HBDBus_SOURCES
    "${HBDBUS_DIR}/common/libhbdbus.c"
    "${HBDBUS_DIR}/common/helpers.c"
    "${HBDBUS_DIR}/common/avl.c"
    "${HBDBUS_DIR}/common/avl-cmp.c"
    "${HBDBUS_DIR}/common/kvlist.c"
    "${HBDBUS_DIR}/common/sign_verify_rsa_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_hmac_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_dummy.c"
)

set(HBDBus_LIBRARIES)
set(HBDBus_INTERFACE_LIBRARIES HBDBus)
set(HBDBus_INTERFACE_INCLUDE_DIRECTORIES ${HBDBus_PRIVATE_FRAMEWORK_HEADERS_DIR})

HBDBUS_FRAMEWORK_DECLARE(HBDBus)
HBDBUS_INCLUDE_CONFIG_FILES_IF_EXISTS()

HBDBUS_WRAP_SOURCELIST(${HBDBus_SOURCES})

HBDBUS_COPY_FILES(HBDBus_CopyPrivateHeaders
    DESTINATION ${HBDBus_PRIVATE_FRAMEWORK_HEADERS_DIR}/hbdbus
    FILES ${HBDBus_PRIVATE_FRAMEWORK_HEADERS}
    FLATTENED
)

list(APPEND HBDBus_INTERFACE_DEPENDENCIES HBDBus_CopyPrivateHeaders)
if (NOT INTERNAL_BUILD)
    add_dependencies(HBDBus_CopyPrivateHeaders HBDBus)
endif ()

list(APPEND HBDBus_LIBRARIES
    PurC::PurC
    ${GLIB_LIBRARIES}
)

HBDBUS_COMPUTE_SOURCES(HBDBus)
HBDBUS_FRAMEWORK(HBDBus)
HBDBUS_FRAMEWORK_TARGET(HBDBus)

if (${HBDBus_LIBRARY_TYPE} MATCHES "SHARED")
    set_target_properties(HBDBus PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
    install(TARGETS HBDBus DESTINATION "${LIB_INSTALL_DIR}")
endif ()

if (MSVC)
    set_target_properties(HBDBus PROPERTIES
        COMPILE_PDB_NAME ${HBDBus_OUTPUT_NAME}
    )
endif ()

install(TARGETS HBDBus DESTINATION "${LIB_INSTALL_DIR}/")

set(HBDBus_FRAMEWORK_HEADERS
    "${HBDBUS_DIR}/include/hbdbus.h"
)

set(HBDBus_INSTALLED_HEADERS ${HBDBus_FRAMEWORK_HEADERS})

install(FILES ${HBDBus_INSTALLED_HEADERS}
        DESTINATION "${HEADER_INSTALL_DIR}/hbdbus"
)

include(target/HBDBus)

HBDBUS_EXECUTABLE_DECLARE(hbdbusd)

list(APPEND hbdbusd_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDBUS_DIR}"
    "${HBDBUS_DIR}/include"
    "${HBDBus_DERIVED_SOURCES_DIR}"
    "${FORWARDING_HEADERS_DIR}/hbdbus"
    "${GLIB_INCLUDE_DIRS}"
)

HBDBUS_EXECUTABLE(hbdbusd)

list(APPEND hbdbusd_SOURCES
    "${HBDBUS_DIR}/common/gslist.c"
    "${HBDBUS_DIR}/common/safe-list.c"
    "${HBDBUS_DIR}/common/helpers.c"
    "${HBDBUS_DIR}/common/kvlist.c"
    "${HBDBUS_DIR}/common/avl.c"
    "${HBDBUS_DIR}/common/avl-cmp.c"
    "${HBDBUS_DIR}/common/printbuf.c"
    "${HBDBUS_DIR}/common/sign_verify_rsa_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_hmac_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_dummy.c"
    "${HBDBUS_DIR}/sbin/websocket.c"
    "${HBDBUS_DIR}/sbin/unixsocket.c"
    "${HBDBUS_DIR}/sbin/server.c"
    "${HBDBUS_DIR}/sbin/endpoint.c"
    "${HBDBUS_DIR}/sbin/builtin-endpoint.c"
    "${HBDBUS_DIR}/sbin/pattern-list.c"
)

set(hbdbusd_LIBRARIES
    PurC::PurC
    "${GLIB_LIBRARIES}"
    "${OPENSSL_LIBRARIES}"
)

set_target_properties(hbdbusd PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/sbin"
)

HBDBUS_COMPUTE_SOURCES(hbdbusd)
HBDBUS_FRAMEWORK(hbdbusd)

install(TARGETS hbdbusd DESTINATION "${SYSEXEC_INSTALL_DIR}/")

HBDBUS_EXECUTABLE_DECLARE(hbdbuscl)

list(APPEND hbdbuscl_PRIVATE_INCLUDE_DIRECTORIES
    "${CMAKE_BINARY_DIR}"
    "${HBDBUS_DIR}"
    "${HBDBUS_DIR}/include"
    "${HBDBus_DERIVED_SOURCES_DIR}"
    "${FORWARDING_HEADERS_DIR}/hbdbus"
)

HBDBUS_EXECUTABLE(hbdbuscl)

list(APPEND hbdbuscl_SOURCES
    "${HBDBUS_DIR}/common/libhbdbus.c"
    "${HBDBUS_DIR}/common/helpers.c"
    "${HBDBUS_DIR}/common/avl.c"
    "${HBDBUS_DIR}/common/avl-cmp.c"
    "${HBDBUS_DIR}/common/kvlist.c"
    "${HBDBUS_DIR}/common/sign_verify_rsa_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_hmac_sha256.c"
    "${HBDBUS_DIR}/common/sign_verify_dummy.c"
    "${HBDBUS_DIR}/bin/cmdline.c"
    "${HBDBUS_DIR}/bin/drum-game.c"
)

set(hbdbuscl_LIBRARIES
    PurC::PurC
)

set_target_properties(hbdbuscl PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

HBDBUS_COMPUTE_SOURCES(hbdbuscl)
HBDBUS_FRAMEWORK(hbdbuscl)

install(TARGETS hbdbuscl DESTINATION "${EXEC_INSTALL_DIR}/")

