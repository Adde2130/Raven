V ?= 0

ifeq ($(V),1)
ECHO :=
else
ECHO := @
endif

SRC_DIR := src
BUILD_DIR_32 := build32
BUILD_DIR_64 := build64
INCLUDE := $(dir $(wildcard $(SRC_DIR)/*)) $(dir $(wildcard $(SRC_DIR)/*/*))

# Separate C and C++ source files
C_SRCS := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
CPP_SRCS := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/*/*.cpp)

# Separate C and C++ object files for 32-bit and 64-bit
C_OBJS_32 := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR_32)/%.o,$(C_SRCS))
CPP_OBJS_32 := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR_32)/%.o,$(CPP_SRCS))
C_OBJS_64 := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR_64)/%.o,$(C_SRCS))
CPP_OBJS_64 := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR_64)/%.o,$(CPP_SRCS))

# All object files for 32-bit and 64-bit
OBJS_32 := $(C_OBJS_32) $(CPP_OBJS_32)
OBJS_64 := $(C_OBJS_64) $(CPP_OBJS_64)

# Target DLL
TARGET32 := Raven32.dll
TARGET64 := Raven64.dll

# MinGW Paths
MINGW32_PATH := C:/mingw32/bin
MINGW64_PATH := C:/mingw64/bin

# Compilers
CC32 := $(MINGW32_PATH)/gcc
CC64 := $(MINGW64_PATH)/gcc
CXX32 := $(MINGW32_PATH)/g++
CXX64 := $(MINGW64_PATH)/g++

CFLAGS := -g -Wall -Wextra -O0 $(addprefix -I,$(INCLUDE)) -shared -static-libgcc
CXXFLAGS := $(CFLAGS) -static-libstdc++
LDFLAGS := 

.PHONY: all clean

all: $(BUILD_DIR_32) $(BUILD_DIR_64) $(TARGET32) $(TARGET64)
	@echo "Successfully built Raven"

$(BUILD_DIR_32) $(BUILD_DIR_64):
	$(ECHO)mkdir -p $@

$(BUILD_DIR_32)/%.o: $(SRC_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC32) $(CFLAGS) -m32 -c $< -o $@

$(BUILD_DIR_64)/%.o: $(SRC_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC64) $(CFLAGS) -m64 -c $< -o $@

$(BUILD_DIR_32)/%.o: $(SRC_DIR)/%.cpp
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CXX32) $(CXXFLAGS) -m32 -c $< -o $@

$(BUILD_DIR_64)/%.o: $(SRC_DIR)/%.cpp
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CXX64) $(CXXFLAGS) -m64 -c $< -o $@

$(TARGET32): $(OBJS_32)
	$(ECHO)$(CXX32) $(CFLAGS) -m32 $^ -o $@ $(LDFLAGS) 1>linkerror32 2>&1

$(TARGET64): $(OBJS_64)
	$(ECHO)$(CXX64) $(CFLAGS) -m64 $^ -o $@ $(LDFLAGS) 1>linkerror64 2>&1

clean:
	rm -rf $(BUILD_DIR_32) $(BUILD_DIR_64) $(TARGET32) $(TARGET64)