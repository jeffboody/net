cmake_minimum_required(VERSION 3.4.1)

# Compiler options
add_compile_options(-Wall)

# Submodule library
add_library(net
            STATIC

            # Source
            net_socket.c)

# Linking
target_link_libraries(net

                      # NDK libraries
                      log)
