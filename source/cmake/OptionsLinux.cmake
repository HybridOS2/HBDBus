include(GNUInstallDirs)

HBDBUS_OPTION_BEGIN()

CALCULATE_LIBRARY_VERSIONS_FROM_LIBTOOL_TRIPLE(HBDBUS 0 0 0)

add_definitions(-DBUILDING_LINUX__=1)
add_definitions(-DHBDBUS_API_VERSION_STRING="${HBDBUS_API_VERSION}")

# Finalize the value for all options. Do not attempt to use an option before
# this point, and do not attempt to change any option after this point.
HBDBUS_OPTION_END()

# CMake does not automatically add --whole-archive when building shared objects from
# a list of convenience libraries. This can lead to missing symbols in the final output.
# We add --whole-archive to all libraries manually to prevent the linker from trimming
# symbols that we actually need later. With ld64 on darwin, we use -all_load instead.
macro(ADD_WHOLE_ARCHIVE_TO_LIBRARIES _list_name)
    if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        list(APPEND ${_list_name} -Wl,-all_load)
    else ()
        set(_tmp)
        foreach (item IN LISTS ${_list_name})
            if ("${item}" STREQUAL "PRIVATE" OR "${item}" STREQUAL "PUBLIC")
                list(APPEND _tmp "${item}")
            else ()
                list(APPEND _tmp -Wl,--whole-archive "${item}" -Wl,--no-whole-archive)
            endif ()
        endforeach ()
        set(${_list_name} ${_tmp})
    endif ()
endmacro()

#include(BubblewrapSandboxChecks)
