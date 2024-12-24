TARGET := common-plugin.so
SOURCES := plugin.c

CC := gcc
CFLAGS := -Wall -Wextra -O2 -fPIC -DHAVE_STDINT_H

DEP_FILES := $(TARGET:.so=.d)

.PHONY: all clean

all: $(TARGET)

clean:
	$(RM) $(TARGET) $(DEP_FILES)

$(TARGET): $(SOURCES)
	$(CC) -shared $(CFLAGS) -MD -MMD -o $@ $^

-include $(DEP_FILES)