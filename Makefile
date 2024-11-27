PROJECT = enumprotections

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
OCPY   := objcopy

CFLAGS := -Wall -Werror -Wno-pointer-to-int-cast -s -fPIC 
IMPORTS := src/imports_$(PROJECT)86.txt
IMPORTS64 := src/imports_$(PROJECT)64.txt

.DEFAULT: all
.PHONY: all
all: bof

.PHONY: bof
bof: $(PROJECT).x64.o $(PROJECT).x86.o

$(PROJECT).x64.o: src/main.c
	@echo Compiling x64 BOF and patching symbols
	@$(CCX64) -c $< -o dist/$@ $(CFLAGS)
	@$(OCPY) --redefine-syms=$(IMPORTS64) dist/$@ dist/$@

$(PROJECT).x86.o: src/main.c
	@echo Compiling x86 BOF and patching symbols
	@$(CCX86) -c $< -o dist/$@ $(CFLAGS)
	@$(OCPY) --redefine-syms=$(IMPORTS) dist/$@ dist/$@

.PHONY: clean
clean:
	rm -f dist/$(PROJECT)x64.o
	rm -f dist/$(PROJECT)x86.o