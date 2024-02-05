cmake_minimum_required(VERSION 3.12)

set(PROJECT test)

project(${PROJECT} VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fs_unit_test
        test.h
        test.cc
        ../src/utils/fs.h
        ../src/utils/fs.cc
        fs_unit_test.cc)
add_test(NAME fs_unit_test COMMAND fs_unit_test)

add_executable(cgroup_unit_test
        test.h
        test.cc
        ../src/cgroup.h
        ../src/cgroup.cc
        ../src/utils/strconv.h
        ../src/utils/strconv.cc
        ../src/utils/fs.h
        ../src/utils/fs.cc
        ../src/utils/now.h
        ../src/utils/now.cc
        ../src/utils/log.h
        ../src/utils/log.cc
        ../src/seccomp.h
        ../src/seccomp.cc
        cgroup_unit_test.cc)
add_test(NAME cgroup_unit_test COMMAND cgroup_unit_test)
target_compile_definitions(cgroup_unit_test PUBLIC -DUNIT_TEST)


if($ENV{NOSECCOMP})
    add_definitions(-DLIBSECCOMP_VERSION_MAJOR=0)
else()
    execute_process(COMMAND pkg-config --modversion libseccomp OUTPUT_VARIABLE LIBSECCOMP_VERSION)
    if(${LIBSECCOMP_VERSION} MATCHES "2.*")
        target_compile_definitions(cgroup_unit_test PUBLIC -DLIBSECCOMP_VERSION_MAJOR=2)
        find_package(PkgConfig)
        pkg_search_module(SECCOMP REQUIRED libseccomp)
        target_include_directories(cgroup_unit_test BEFORE PRIVATE ${SECCOMP_INCLUDE_DIRS})
        target_link_libraries(cgroup_unit_test PUBLIC ${SECCOMP_LIBRARIES})
    endif()
endif()

add_custom_command(TARGET cgroup_unit_test POST_BUILD COMMAND sudo install -D -m4550 -oroot -glrun ${CMAKE_CURRENT_BINARY_DIR}/cgroup_unit_test ${CMAKE_BINARY_DIR}/cgroup_unit_test)

add_executable(strconv_unit_test
        test.h
        test.cc
        ../src/utils/strconv.h
        ../src/utils/strconv.cc
        strconv_unit_test.cc)
add_test(NAME strconv_unit_test COMMAND strconv_unit_test)

add_executable(integration_test
        test.h
        test.cc
        integration_test.cc)
add_test(NAME integration_test COMMAND integration_test)
add_custom_command(TARGET integration_test POST_BUILD COMMAND sudo install -D -m4550 -oroot -glrun ${CMAKE_CURRENT_BINARY_DIR}/integration_test ${CMAKE_BINARY_DIR}/integration_test)
