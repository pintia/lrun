cmake_minimum_required(VERSION 3.12)

project(lrun VERSION 0.1 LANGUAGES CXX)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)

if($ENV{NOSECCOMP})
    add_definitions(-DLIBSECCOMP_VERSION_MAJOR=0)
else()
    execute_process(COMMAND pkg-config --modversion libseccomp OUTPUT_VARIABLE LIBSECCOMP_VERSION)
    if(${LIBSECCOMP_VERSION} MATCHES "2.*")
        add_definitions(-DLIBSECCOMP_VERSION_MAJOR=2)
    endif()
endif()

execute_process(COMMAND bash -c "mount -l | grep \"/sys/fs/cgroup type cgroup2\"" RESULT_VARIABLE CGROUP_CHECK)
if(${CGROUP_CHECK} EQUAL "0")
    add_definitions(-DCGROUP_VERSION=2)
else()
    add_definitions(-DCGROUP_VERSION=1)
endif()