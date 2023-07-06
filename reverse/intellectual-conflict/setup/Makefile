CXX=g++-13
CXXFLAGS=-Wall -Werror -Wextra -Wc++20-extensions -s

BUILD_DIR=./build
SRC_DIR=./src
LIBS_DIR=./include

vm.bin: $(SRC_DIR)/main.cpp
	$(CXX) $(CXXFLAGS) -I$(LIBS_DIR) -o $@ $<
