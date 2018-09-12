cmake_minimum_required(VERSION 3.0)
project(NGHTTP2_HASHTABLE)
#SET(CMAKE_C_COMPILER g++)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

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
	"${CMAKE_CURRENT_SOURCE_DIR}/nghttp2"
	"${CMAKE_CURRENT_SOURCE_DIR}/hashtable"
	"${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader"
    "${CMAKE_CURRENT_SOURCE_DIR}/mem2str2mem"
	"${CMAKE_CURRENT_SOURCE_DIR}/JsonLib"
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
	${CMAKE_CURRENT_SOURCE_DIR}/runEsm/esmMain.c
	${CMAKE_CURRENT_SOURCE_DIR}/nghttp2/http_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hashtable/obj_hashtable.c
	${CMAKE_CURRENT_SOURCE_DIR}/hashtable/hashAPI.c
	${CMAKE_CURRENT_SOURCE_DIR}/mem2str2mem/mem2str2mem.c
	${CMAKE_CURRENT_SOURCE_DIR}/JsonLib/cJSON.c
    ${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/dynamic_memory_check.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nghttp2/libevent-server-mdfy.c
	${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/backtrace.c
	${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/esm_data_context.c
	#${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/mme_config.c
)

#add_executable(
#    Client 
#	${CMAKE_CURRENT_SOURCE_DIR}/test/Client.c
#	${CMAKE_CURRENT_SOURCE_DIR}/nghttp2/http_parser.c
#    ${CMAKE_CURRENT_SOURCE_DIR}/hashtable/obj_hashtable.c
#	${CMAKE_CURRENT_SOURCE_DIR}/hashtable/hashAPI.c
#    ${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/bstrlib.c
#    ${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/dynamic_memory_check.c
#	${CMAKE_CURRENT_SOURCE_DIR}/oaiHeader/backtrace.c
#	${CMAKE_CURRENT_SOURCE_DIR}/mem2str2mem/mem2str2mem.c
#)
set(LFDS611_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/liblfds611.a)
set(BSTR_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/libBSTR.a)
set(LFDS_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib/libLFDS.a)
target_link_libraries(esm m LIBRT::LIBRT ${LFDS611_PATH} ${BSTR_PATH} ${LFDS_PATH})

#add_executable(
#	Client
#	${CMAKE_CURRENT_SOURCE_DIR}/Client.c
#	${CMAKE_CURRENT_SOURCE_DIR}/mem2str2mem.c
#	)
