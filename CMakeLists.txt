cmake_minimum_required(VERSION 2.8.3)
project(python-cryptonote)

find_package(PythonInterp)
find_package(PythonLibs)

set(BOOST_PYTHON_LIB python)
if (${PYTHON_VERSION_MAJOR} EQUAL 3)
    if(${APPLE})
        set(BOOST_PYTHON_LIB python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR})
    elseif(${UNIX})
        set(BOOST_PYTHON_LIB python-py${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR})
    endif()
endif()

find_package(Boost REQUIRED COMPONENTS system ${BOOST_PYTHON_LIB})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes -std=c11")

include_directories(${Boost_INCLUDE_DIRS} ${PYTHON_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES} ${PYTHON_LIBRARIES})

add_subdirectory(src)
