MODULE_NAME = RavenPy
SRCDIR = src
OBJDIR = obj
INCDIR = include 
RAVENINC = ../include
SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))
SHARED_OBJ = $(MODULE_NAME).pyd

PYTHON_PATH = "C:/Users/Adde/AppData/Local/Programs/Python/Python311"
PY_INCLUDE = $(PYTHON_PATH)/include
PY_LIB = $(PYTHON_PATH)

CC = C:/msys64/mingw64/bin/gcc
CFLAGS = -Wall -fPIC -D MS_WIN64 -O3 -I$(PY_INCLUDE) -I$(INCDIR) -I$(RAVENINC)
LDFLAGS =  -lpsapi -lshlwapi -lntdll -lshlwapi -lshell32 -L$(PY_LIB) -lpython311 -L../lib -lRaven64

all: $(SHARED_OBJ)

$(SHARED_OBJ): $(OBJ)
	$(CC) -shared $^ -o $(SHARED_OBJ) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR)
	rm -f $(SHARED_OBJ)

install:
	$(PYTHON_PATH)/python setup.py install
