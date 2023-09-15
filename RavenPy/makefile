MODULE_NAME = RavenPy
SRCDIR = src
OBJDIR = obj
INCDIR = E:/Visual Studio Code Workspace/Raven/include
SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))
SHARED_OBJ = $(MODULE_NAME).pyd

PYTHON_PATH = C:/Users/andsa/AppData/Local/Programs/Python/Python36
PY_INCLUDE = $(PYTHON_PATH)/include
PY_LIB = $(PYTHON_PATH)/libs

CC = gcc
CFLAGS = -Wall -fPIC -I$(PY_INCLUDE) -I$(INCDIR)
LDFLAGS = -L$(PY_LIB) -lpython36

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