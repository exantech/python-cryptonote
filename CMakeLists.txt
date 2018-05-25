cmake_minimum_required(VERSION 2.8.3)
project(python-cryptonote)

find_package(PythonInterp)
find_package(PythonLibs)

if (${PYTHON_VERSION_MAJOR} EQUAL 3)
    find_package(Boost COMPONENTS system python3)
else()
    find_package(Boost COMPONENTS system python)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")

include_directories(${Boost_INCLUDE_DIRS} ${PYTHON_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES} ${PYTHON_LIBRARIES})

add_subdirectory(src)
