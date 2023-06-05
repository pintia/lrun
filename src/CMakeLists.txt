cmake_minimum_required(VERSION 3.12)

set(PROJECT lrun)

project(${PROJECT} VERSION 0.1 LANGUAGES CXX)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

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