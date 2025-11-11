CXX = g++
CXXFLAGS = -O3 -Wall -Wextra
TARGET = excel_bypass
SRCDIR = .
COMMONDIR = common

SOURCES = $(SRCDIR)/main.c $(COMMONDIR)/file_util.c
INCLUDES = -I$(COMMONDIR)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

install-deps:
	# No external dependencies needed for lightweight version

.PHONY: clean install-deps