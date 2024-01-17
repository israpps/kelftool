rwildcard = $(foreach d, $(wildcard $1*), $(filter $(subst *, %, $2), $d) $(call rwildcard, $d/, $2))

CXX	= g++
LD	= ld

name := kelftool

dir_source := src
dir_build := build

CXXFLAGS = --std=c++17
LDLIBS = -lcrypto

# next flags only for macos
# change paths to your location of openssl@1.1
ifdef HOMEBREW_PREFIX
	OUTPUT_OPTION += -I$(HOMEBREW_PREFIX)/opt/openssl@1.1/include
	LDLIBS += -L$(HOMEBREW_PREFIX)/opt/openssl@1.1/lib
endif

objects =	$(patsubst $(dir_source)/%.cpp, $(dir_build)/%.o, \
			$(call rwildcard, $(dir_source), *.cpp))

.PHONY: all
all: $(dir_build)/$(name)

.PHONY: clean
clean:
	@rm -rf $(dir_build)/$(name) $(objects)

$(dir_build)/$(name): $(objects)
	$(LINK.cc) $^ $(LDLIBS) $(OUTPUT_OPTION) -o $@

$(dir_build)/%.o: $(dir_source)/%.cpp
	@mkdir -p "$(@D)"
	$(COMPILE.cpp) $< $(OUTPUT_OPTION) -o $@
