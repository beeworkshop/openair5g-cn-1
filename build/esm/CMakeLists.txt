cmake_minimum_required(VERSION 3.0)
set (OPENAIRCN_DIR  $ENV{OPENAIRCN_DIR})
project(NGHTTP2_HASHTABLE)
#SET(CMAKE_C_COMPILER g++)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake" ${CMAKE_MODULE_PATH})

find_package(OpenSSL 1.0.1)
set(HAVE_OPENSSL ${OPENSSL_FOUND})
if(HAVE_OPENSSL)
	set(OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
	set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES})
	message(${OPENSSL_INCLUDE_DIRS})
	message(${OPENSSL_LIBRARIES})
	message("found openssl")
else()
	message("sorry")
endif()

find_package(Libev 4.11)
set(HAVE_LIBEVENT ${LIBEV_FOUND})
if(HAVE_LIBEVENT)
	set(LIBEVENT_INCLUDE_DIRS ${LIBEV_INCLUDE_DIR})
	set(LIBEVENT_LIBRARIES ${LIBEV_LIBRARIES})
	message(${LIBEVENT_INCLUDE_DIRS})
	message(${LIBEVENT_LIBRARIES})
else()
	message("don't find libev")
endif()

find_package(Libevent COMPONENTS libevent openssl)
set(ENABLE_EXAMPLES_DEFAULT ${LIBEVENT_OPENSSL_FOUND})
if(ENABLE_EXAMPLES_DEFAULT)
	set(LIBEVENT_OPENSSL_LIBRARIES ${LIBEVENT_LIBRARIES})
	message(${LIBEVENT_OPENSSL_LIBRARIES})
else()
	message("sorry")
endif()

find_package(Libcares 1.7.5)
set(HAVE_LIBCARES ${LIBCARES_FOUND})
if(HAVE_LIBCARES)
	set(LIBCARES_INCLUDE_DIRS ${LIBCARES_INCLUDE_DIR})
	set(LIBCARES_LIBRARIES ${LIBCARES_LIBRARIES})
	message(${LIBCARES_INCLUDE_DIRS})
	message(${LIBCARES_LIBRARIES})
else()
	message("don't find libcares")
endif()

set(APP_LIBRARIES)
find_package(Threads)
set(HAVE_THREADS ${THREADS_FOUND})
if(HAVE_THREADS)
	message("found threads")
	if(CMAKE_USE_PTHREADS_INIT)
		message("use pthreads init")
		list(APPEND APP_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
	endif()
endif()
find_package(LibRt)
include_directories(
	"${OPENAIRCN_DIR}/src/oai_esm/nghttp2"
	"${OPENAIRCN_DIR}/src/oai_esm/hashtable"
	"${OPENAIRCN_DIR}/src/oai_esm/oaiHeader"
    "${OPENAIRCN_DIR}/src/oai_esm/mem2str2mem"
	"${OPENAIRCN_DIR}/src/oai_esm/JsonLib"
	${LIBEVENT_INCLUDE_DIRS}
	${OPENSSL_INCLUDE_DIRS}
	)
link_libraries(
	nghttp2
	${LIBEVENT_OPENSSL_LIBRARIES}
	${OPENSSL_LIBRARIES}
	${APP_LIBRARIES}
	)

add_executable(
	esm 
	${OPENAIRCN_DIR}/src/oai_esm/runEsm/esmMain.c
	${OPENAIRCN_DIR}/src/oai_esm/nghttp2/http_parser.c
    ${OPENAIRCN_DIR}/src/oai_esm/hashtable/obj_hashtable.c
	${OPENAIRCN_DIR}/src/oai_esm/hashtable/hashAPI.c
	${OPENAIRCN_DIR}/src/oai_esm/mem2str2mem/mem2str2mem.c
	${OPENAIRCN_DIR}/src/oai_esm/JsonLib/cJSON.c
    ${OPENAIRCN_DIR}/src/oai_esm/oaiHeader/dynamic_memory_check.c
    ${OPENAIRCN_DIR}/src/oai_esm/nghttp2/libevent-server-mdfy.c
	${OPENAIRCN_DIR}/src/oai_esm/oaiHeader/backtrace.c
	${OPENAIRCN_DIR}/src/oai_esm/oaiHeader/esm_data_context.c
	#${OPENAIRCN_DIR}/oaiHeader/mme_config.c
)

#add_executable(
#    Client 
#	${OPENAIRCN_DIR}/test/Client.c
#	${OPENAIRCN_DIR}/nghttp2/http_parser.c
#    ${OPENAIRCN_DIR}/hashtable/obj_hashtable.c
#	${OPENAIRCN_DIR}/hashtable/hashAPI.c
#    ${OPENAIRCN_DIR}/oaiHeader/bstrlib.c
#    ${OPENAIRCN_DIR}/oaiHeader/dynamic_memory_check.c
#	${OPENAIRCN_DIR}/oaiHeader/backtrace.c
#	${OPENAIRCN_DIR}/mem2str2mem/mem2str2mem.c
#)
set(LFDS611_PATH ${OPENAIRCN_DIR}/src/oai_esm/lib/liblfds611.a)
set(BSTR_PATH ${OPENAIRCN_DIR}/src/oai_esm/lib/libBSTR.a)
set(LFDS_PATH ${OPENAIRCN_DIR}/src/oai_esm/lib/libLFDS.a)
target_link_libraries(esm m LIBRT::LIBRT ${LFDS611_PATH} ${BSTR_PATH} ${LFDS_PATH})

#add_executable(
#	Client
#	${OPENAIRCN_DIR}/Client.c
#	${OPENAIRCN_DIR}/mem2str2mem.c
#	)
