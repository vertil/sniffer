cmake_minimum_required(VERSION 3.18)
project(Npcap CXX C)

add_executable(snif

                            main.cpp
                            #Include/pcap.h
                            )


target_include_directories(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Include)
target_include_directories(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Lib)
#for x64
target_link_libraries(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/Packet.lib)
target_link_libraries(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Lib/x64/wpcap.lib)
#for x32
#target_link_libraries(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Lib/Packet.lib)
#target_link_libraries(snif PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Lib/wpcap.lib)


# Add SDL2 library
#find_package(OpenSSL REQUIRED)
#target_link_libraries(snif PUBLIC OpenSSL::SSL)

#target_link_libraries(snif PUBLIC C:/Windows/System32/Npcap/Packet.dll)
#target_link_libraries(snif PUBLIC C:/Windows/System32/Npcap/wpcap.dll)


target_compile_features(snif PUBLIC cxx_std_20)


