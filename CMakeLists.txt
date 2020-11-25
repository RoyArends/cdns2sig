CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(cdns2sig CXX)

SET(CMAKE_CXX_STANDARD 11)

SET(CMAKE_CXX_FLAGS "-Wall -O2 -g ${CMAKE_CXX_FLAGS}")

INCLUDE_DIRECTORIES(src include ../cdnsrdr/lib)

SET(CDNS2SIG_LIBRARY_FILES
   ../cdnsrdr/lib/cbor.cpp
   ../cdnsrdr/lib/cdns.cpp
)

ADD_EXECUTABLE(cdns2sig
   src/cdns2sig.cpp
   ../cdnsrdr/lib/cbor.cpp
   ../cdnsrdr/lib/cdns.cpp
)

INSTALL(TARGETS cdns2sig
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         PUBLIC_HEADER DESTINATION include)
