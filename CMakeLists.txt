CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(cdns2sig CXX)

SET(CMAKE_CXX_STANDARD 11)

SET(CMAKE_CXX_FLAGS "-Wall -O2 -g ${CMAKE_CXX_FLAGS}")

INCLUDE_DIRECTORIES(src include cdns/lib)

SET(CDNS2SIG_LIBRARY_FILES
   cdns/lib/cbor.cpp
   cdns/lib/cdns.cpp
)

ADD_EXECUTABLE(cdns2sig
   src/cdns2sig.cpp
   cdns/lib/cbor.cpp
   cdns/lib/cdns.cpp
)

ADD_EXECUTABLE(cdns2line
   src/cdns2line.cpp
   cdns/lib/cbor.cpp
   cdns/lib/cdns.cpp
)

INSTALL(TARGETS cdns2sig cdns2line
         RUNTIME DESTINATION bin
         LIBRARY DESTINATION lib
         PUBLIC_HEADER DESTINATION include)

