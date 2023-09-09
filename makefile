SRC_DIR := src
BUILD_DIR := build
INCLUDE := $(dir $(wildcard $(SRC_DIR)/*)) $(dir $(wildcard $(SRC_DIR)/*/*)) 

# Separate C and C++ source files
C_SRCS := $(shell find $(SRC_DIR) -name '*.c')
CPP_SRCS := $(shell find $(SRC_DIR) -name '*.cpp')

# Separate C and C++ object files
C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
CPP_OBJS := $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(CPP_SRCS))

# All object files
OBJS := $(C_OBJS) $(CPP_OBJS)

# Target DLL
TARGET := Raven.dll

CC := gcc
CXX := g++
CFLAGS := -g -Wall -Wextra -O0 $(addprefix -I,$(INCLUDE)) -shared 
CXXFLAGS := $(CFLAGS)
LDFLAGS := 

.PHONY: all clean

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CXX) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)