cmake_minimum_required(VERSION 3.12)

set(PROJECT lrun)

project(${PROJECT} VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CPP_HEADERS
        cgroup.h
        config.h
        fs_tracer.h
        seccomp.h
        version.h
        options/options.h
        utils/ensure.h
        utils/for_each.h
        utils/fs.h
        utils/linux_only.h
        utils/log.h
        utils/now.h
        utils/re.h
        utils/strconv.h)

set(CPP_SOURCES
        cgroup.cc
        cgroup_factory.cc
        cgroupv1.cc
        cgroupv2.cc
        config.cc
        fs_tracer.cc
        lrun.cc
        seccomp.cc
        options/fopen_filter.cc
        options/help.cc
        options/parse.cc
        utils/fs.cc
        utils/log.cc
        utils/now.cc
        utils/re.cc
        utils/strconv.cc)

add_executable(lrun ${CPP_HEADERS} ${CPP_SOURCES})

if($ENV{NOSECCOMP})
    add_definitions(-DLIBSECCOMP_VERSION_MAJOR=0)
else()
    execute_process(COMMAND pkg-config --modversion libseccomp OUTPUT_VARIABLE LIBSECCOMP_VERSION)
    if(${LIBSECCOMP_VERSION} MATCHES "2.*")
        target_compile_definitions(lrun PUBLIC -DLIBSECCOMP_VERSION_MAJOR=2)
        find_package(PkgConfig)
        pkg_search_module(SECCOMP REQUIRED libseccomp)
        target_include_directories(lrun BEFORE PRIVATE ${SECCOMP_INCLUDE_DIRS})
        target_link_libraries(lrun PUBLIC ${SECCOMP_LIBRARIES})
    endif()
endif()

add_custom_command(TARGET lrun POST_BUILD COMMAND sudo install -D -m4550 -oroot -glrun ${CMAKE_CURRENT_BINARY_DIR}/lrun ${CMAKE_BINARY_DIR}/lrun)