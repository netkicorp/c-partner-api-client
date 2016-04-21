cmake_minimum_required(VERSION 3.5)
project(partner_example)
project(wnresolver_example)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

link_directories(/usr/lib)

set(SOURCE_FILES cJSON.c netki.c wnresolver.c base64.c sha2.c)

add_executable(partner_example ${SOURCE_FILES} examples/partner.c examples/curlHttpCallbackImpl.c)
add_executable(wnresolver_example ${SOURCE_FILES} examples/wnresolver.c examples/curlHttpCallbackImpl.c)
add_library(nkpartner STATIC ${SOURCE_FILES})

target_link_libraries(nkpartner secp256k1)
target_link_libraries(nkpartner unbound)

target_link_libraries(partner_example curl)
target_link_libraries(partner_example secp256k1)
target_link_libraries(partner_example unbound)

target_link_libraries(wnresolver_example curl)
target_link_libraries(wnresolver_example secp256k1)
target_link_libraries(wnresolver_example unbound)
