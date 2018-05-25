add_subdirectory(crypto)

set(MODULE_NAME cryptonote)
python_add_module(${MODULE_NAME} main.cpp)
target_link_libraries(${MODULE_NAME} cncrypto ${Boost_SYSTEM_LIBRARY})

set_target_properties(${MODULE_NAME} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
