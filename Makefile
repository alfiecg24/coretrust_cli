CC = xcrun clang
LDID = ldid -S
SDK_PATH_MACOS := $(shell xcrun --sdk macosx --show-sdk-path)
SDK_PATH_IOS := $(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS = -Iinclude
LDFLAGS = -Llib
LDFLAGS_IOS = -Llib/ios
LIBS = -lchoma

.PHONY: all clean

all: dirs macos ios

dirs:
	mkdir -p output/ios

macos: main.c
	$(CC) -isysroot $(SDK_PATH_MACOS) $^ -o output/coretrust_cli -Wl,-force_load,lib/AuthKit.tbd $(CFLAGS) $(LDFLAGS) $(LIBS)
	$(LDID) output/coretrust_cli

ios: main.c
	$(CC) -arch arm64 -isysroot $(SDK_PATH_IOS) $^ -o output/ios/coretrust_cli -Wl,-force_load,lib/ios/MobileInBoxUpdate.tbd $(CFLAGS) $(LDFLAGS_IOS) $(LIBS)
	$(LDID) output/ios/coretrust_cli

clean:
	@rm -rf output