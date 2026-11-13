cmake_minimum_required(VERSION 3.20)

project(relay LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(librelay STATIC
    src/elf.cpp
)
set_target_properties(librelay PROPERTIES
    PREFIX ""
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(librelay PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/relay
)
#FetchContent_Declare(quant-backend
#    GIT_REPOSITORY https://github.com/quant-lang/qu-backend.git
#    GIT_TAG        main
#    GIT_SHALLOW    TRUE
#)
#FetchContent_MakeAvailable(quant-backend)
#target_link_libraries(librelay PUBLIC quant-backend)

find_package(Zydis REQUIRED)
target_link_libraries(librelay PRIVATE Zydis::Zydis)

FetchContent_Declare(asmjit
    GIT_REPOSITORY https://github.com/asmjit/asmjit
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asmjit)
target_link_libraries(librelay PUBLIC asmjit)

target_compile_options(librelay PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)
add_executable(relay
    src/main.cpp
)
target_link_libraries(relay PRIVATE librelay)
