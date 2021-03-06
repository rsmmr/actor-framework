set(LABEL_EXPR "$ENV{label_exp}")
if ("${LABEL_EXPR}" MATCHES "gcc" OR "${LABEL_EXPR}" MATCHES "gcovr")
  message(STATUS "Set CXX to g++ based on label_expr content")
  set(CMAKE_C_COMPILER "gcc" CACHE PATH "C compiler option")
  set(CMAKE_CXX_COMPILER "g++" CACHE PATH "C++ compiler option")
  # OpenCL header on OSX do not work with GCC
  if(APPLE)
    set(CAF_NO_OPENCL yes CACHE BOOL "Configure OpenCL module")
  endif(APPLE)
elseif ("${LABEL_EXPR}" MATCHES "clang")
  message(STATUS "Set CXX to clang++ based on label_expr content")
  set(CMAKE_C_COMPILER "clang" CACHE STRING "C compiler option")
  set(CMAKE_CXX_COMPILER "clang++" CACHE STRING "C++ compiler option")
endif()
