if (NOT TARGET HBDBus::HBDBus)
    if (NOT INTERNAL_BUILD)
        message(FATAL_ERROR "HBDBus::HBDBus target not found")
    endif ()

    # This should be moved to an if block if the Apple Mac/iOS build moves completely to CMake
    # Just assuming Windows for the moment
    add_library(HBDBus::HBDBus STATIC IMPORTED)
    set_target_properties(HBDBus::HBDBus PROPERTIES
        IMPORTED_LOCATION ${WEBKIT_LIBRARIES_LINK_DIR}/HBDBus${DEBUG_SUFFIX}.lib
    )
    set(HBDBus_PRIVATE_FRAMEWORK_HEADERS_DIR "${CMAKE_BINARY_DIR}/../include/private")
    target_include_directories(HBDBus::HBDBus INTERFACE
        ${HBDBus_PRIVATE_FRAMEWORK_HEADERS_DIR}
    )
endif ()
