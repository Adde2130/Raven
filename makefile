V ?= 0

ifeq ($(V),1)
ECHO :=
else
ECHO := @
endif

SRC_DIR := src
VENDOR_DIR := vendor
BUILD_DIR_32 := build32
BUILD_DIR_64 := build64
LIB_DIR := lib

INCLUDE := include $(dir $(wildcard $(SRC_DIR)/*/*)) $(dir $(wildcard $(VENDOR_DIR)/*/*))

# All source files
SRCS := $(wildcard $(SRC_DIR)/*/*.c) $(wildcard $(VENDOR_DIR)/*/*.c)

# Object files with subdirectory structure preserved
OBJS_32 := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR_32)/%.o,$(SRCS))
OBJS_32 := $(patsubst $(VENDOR_DIR)/%.c,$(BUILD_DIR_32)/%.o,$(OBJS_32))

OBJS_64 := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR_64)/%.o,$(SRCS))
OBJS_64 := $(patsubst $(VENDOR_DIR)/%.c,$(BUILD_DIR_64)/%.o,$(OBJS_64))

# Targets
TARGET32 := $(LIB_DIR)/Raven32.dll
TARGET64 := $(LIB_DIR)/Raven64.dll
LIB32 := $(LIB_DIR)/libRaven32.a
LIB64 := $(LIB_DIR)/libRaven64.a

# MinGW Paths
MINGW32_PATH := C:/mingw32/bin
MINGW64_PATH := C:/mingw64/bin

# Compilers
CC32 := $(MINGW32_PATH)/gcc
CC64 := $(MINGW64_PATH)/gcc
AR32 := $(MINGW32_PATH)/ar
AR64 := $(MINGW64_PATH)/ar
RANLIB32 := $(MINGW32_PATH)/ranlib
RANLIB64 := $(MINGW64_PATH)/ranlib

CFLAGS := -g -Wall -Wextra -O0 $(addprefix -I,$(INCLUDE))
LDFLAGS := -static -lpsapi -lshlwapi -lntdll -lgdi32

.PHONY: all clean

all: $(BUILD_DIR_32) $(BUILD_DIR_64) $(LIB_DIR) $(TARGET32) $(TARGET64) $(LIB32) $(LIB64)
	@echo "Successfully built Raven"

$(BUILD_DIR_32) $(BUILD_DIR_64) $(LIB_DIR):
	$(ECHO)mkdir -p $@

# Compile rules
$(BUILD_DIR_32)/%.o: $(SRC_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC32) $(CFLAGS) -m32 -c $< -o $@

$(BUILD_DIR_32)/%.o: $(VENDOR_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC32) $(CFLAGS) -m32 -c $< -o $@

$(BUILD_DIR_64)/%.o: $(SRC_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC64) $(CFLAGS) -m64 -c $< -o $@

$(BUILD_DIR_64)/%.o: $(VENDOR_DIR)/%.c
	$(ECHO)mkdir -p $(dir $@)
	$(ECHO)$(CC64) $(CFLAGS) -m64 -c $< -o $@

# Shared library
$(TARGET32): $(OBJS_32)
	$(ECHO)$(CC32) -shared $(CFLAGS) -m32 $^ -o $@ $(LDFLAGS) 1>linkerror32 2>&1

$(TARGET64): $(OBJS_64)
	$(ECHO)$(CC64) -shared $(CFLAGS) -m64 $^ -o $@ $(LDFLAGS) 1>linkerror64 2>&1

# Static library
$(LIB32): $(OBJS_32)
	$(ECHO)$(AR32) rcs $@ $^
	$(ECHO)$(RANLIB32) $@

$(LIB64): $(OBJS_64)
	$(ECHO)$(AR64) rcs $@ $^
	$(ECHO)$(RANLIB64) $@

clean:
	rm -rf $(BUILD_DIR_32) $(BUILD_DIR_64) $(LIB_DIR) $(TARGET32) $(TARGET64) $(LIB32) $(LIB64)

