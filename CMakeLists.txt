cmake_minimum_required(VERSION 3.4.1)

# Compiler options
add_compile_options(-Wall)

# Submodule library
add_library(net
            STATIC

            # Source
            net_socket.c
            net_socket_wget.c
            net_log.c
            http_stream.c)

# Linking
target_link_libraries(net

                      # NDK libraries
                      log)
