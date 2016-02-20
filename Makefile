# Makefile for use with nmake

TARGET    = meltdown.exe
SOURCES   = meltdown.c deepfreeze.c dfserv.c otp.c pe.c shared.c standard.c
HEADERS   = data.h deepfreeze.h dfserv.h errors.h ioctl.h otp.h pe.h shared.h standard.h
INCPATH   =
LIBPATH   =
LIBS      = crypt32.lib shell32.lib shlwapi.lib version.lib
DEFINES   =
SUBSYSTEM = /SUBSYSTEM:CONSOLE
XP        = Y

# Compiling for Windows XP (x86)
!IF DEFINED(XP) && ("$(XP)" == "Y" || "$(XP)" == "y")
PATH      = %ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Bin;$(PATH)
INCPATH   = $(INCPATH) /I:"%ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Include"
LIBPATH   = $(LIBPATH) /libpath:"%ProgramFiles(x86)%\Microsoft SDKs\Windows\7.1A\Lib"
DEFINES   = $(DEFINES) /D_USING_V110_SDK71_
SUBSYSTEM = /SUBSYSTEM:CONSOLE,5.01
!ENDIF

all: $(TARGET)

clean:
	-@del *.exe *.exp *.lib *.obj 2> NUL

$(TARGET): $(SOURCES) $(HEADERS)
	cl $(SOURCES) /nologo $(INCPATH) $(DEFINES) /link /out:$@ $(SUBSYSTEM) $(LIBPATH) $(LIBS)
