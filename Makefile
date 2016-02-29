# Makefile for use with nmake

PATH      = %ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Bin;$(PATH)
TARGET    = meltdown.exe
SOURCES   = meltdown.c deepfreeze.c dfserv.c otp.c shared.c standard.c
HEADERS   = data.h deepfreeze.h dfserv.h errors.h ioctl.h otp.h shared.h standard.h
INCPATH   = /I:"%ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Include"
LIBPATH   = /libpath:"%ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Lib"
LIBS      = crypt32.lib shell32.lib shlwapi.lib version.lib
DEFINES   = /D_USING_V110_SDK71_
SUBSYSTEM = /SUBSYSTEM:CONSOLE,5.01

all: $(TARGET)

clean:
	-@del *.exe *.exp *.lib *.obj 2> NUL

$(TARGET): $(SOURCES) $(HEADERS)
	cl $(SOURCES) /nologo $(INCPATH) $(DEFINES) /link /out:$@ $(SUBSYSTEM) $(LIBPATH) $(LIBS)
