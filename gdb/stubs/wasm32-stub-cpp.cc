/* GDB stub for the wasm32 target. */
/* Copyright (C) 2016 Free Software Foundation
 * Copyright (C) 2020 Pip Cet <pipcet@gmail.com>
 */
/*   This is originally based on an m68k software stub written by Glenn
     Engel at HP, but has changed quite a bit. 

     Modifications for the SH by Ben Lee and Steve Chamberlain

*/

/****************************************************************************

		THIS SOFTWARE IS NOT COPYRIGHTED

   HP offers the following for use in the public domain.  HP makes no
   warranty with regard to the software or it's performance and the
   user accepts the software "AS IS" with all faults.

   HP DISCLAIMS ANY WARRANTIES, EXPRESS OR IMPLIED, WITH REGARD
   TO THIS SOFTWARE INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

****************************************************************************/
#include <stdio.h>

asm("\t.include \"wasm32-import-macros.s\"\n"

    "\t.import3 debug,write_debug,write_debug\n"
    "\t.import3 debug,read_debug,read_debug\n"
    "\t.import3 debug,check_debug,check_debug\n"
    "\t.import3 debug,wait_debug,wait_debug\n");

extern "C" {
extern int read_debug(char *, int) __attribute__((stackcall));
extern int write_debug(char *, int) __attribute__((stackcall));
extern int wait_debug(void) __attribute__((stackcall));
extern int check_debug(void) __attribute__((stackcall));
};
struct wasm32_registers {
  unsigned long fp;
  unsigned long pc;
  unsigned long sp;
  unsigned long rv;

  unsigned long a[4];

  unsigned long r[8];
  unsigned long i[8];
  double f[8];
};

static void
unpack_registers(struct wasm32_registers *regs, unsigned long *fp,
		 unsigned long rv)
{
  unsigned long regmask = fp[0];
  unsigned long regsize = fp[3];

  regs->fp = (unsigned long)fp;
  regs->pc = fp[1];
  regs->sp = fp[2];
  regs->rv = rv;

  unsigned long *p = fp + 4;

  if (regmask & 0x10) regs->a[0] = *p++;
  if (regmask & 0x20) regs->a[1] = *p++;
  if (regmask & 0x40) regs->a[2] = *p++;
  if (regmask & 0x80) regs->a[3] = *p++;

  if (regmask & 0x100) regs->r[0] = *p++;
  if (regmask & 0x200) regs->r[1] = *p++;
  if (regmask & 0x400) regs->r[2] = *p++;
  if (regmask & 0x800) regs->r[3] = *p++;
  if (regmask & 0x1000) regs->r[4] = *p++;
  if (regmask & 0x2000) regs->r[5] = *p++;
  if (regmask & 0x4000) regs->r[6] = *p++;
  if (regmask & 0x8000) regs->r[7] = *p++;

  if (regmask & 0x10000) regs->i[0] = *p++;
  if (regmask & 0x20000) regs->i[1] = *p++;
  if (regmask & 0x40000) regs->i[2] = *p++;
  if (regmask & 0x80000) regs->i[3] = *p++;
  if (regmask & 0x100000) regs->i[4] = *p++;
  if (regmask & 0x200000) regs->i[5] = *p++;
  if (regmask & 0x400000) regs->i[6] = *p++;
  if (regmask & 0x800000) regs->i[7] = *p++;
}




/* Remote communication protocol.

   A debug packet whose contents are <data>
   is encapsulated for transmission in the form:

	$ <data> # CSUM1 CSUM2

	<data> must be ASCII alphanumeric and cannot include characters
	'$' or '#'.  If <data> starts with two characters followed by
	':', then the existing stubs interpret this as a sequence number.

	CSUM1 and CSUM2 are ascii hex representation of an 8-bit 
	checksum of <data>, the most significant nibble is sent first.
	the hex digits 0-9,a-f are used.

   Receiver responds with:

	+	- if CSUM is correct and ready for next packet
	-	- if CSUM is incorrect

   <data> is as follows:
   All values are encoded in ascii hex digits.

	Request		Packet

	read registers  g
	reply		XX....X		Each byte of register data
					is described by two hex digits.
					Registers are in the internal order
					for GDB, and the bytes in a register
					are in the same order the machine uses.
			or ENN		for an error.

	write regs	GXX..XX		Each byte of register data
					is described by two hex digits.
	reply		OK		for success
			ENN		for an error

        write reg	Pn...=r...	Write register n... with value r...,
					which contains two hex digits for each
					byte in the register (target byte
					order).
	reply		OK		for success
			ENN		for an error
	(not supported by all stubs).

	read mem	mAA..AA,LLLL	AA..AA is address, LLLL is length.
	reply		XX..XX		XX..XX is mem contents
					Can be fewer bytes than requested
					if able to read only part of the data.
			or ENN		NN is errno

	write mem	MAA..AA,LLLL:XX..XX
					AA..AA is address,
					LLLL is number of bytes,
					XX..XX is data
	reply		OK		for success
			ENN		for an error (this includes the case
					where only part of the data was
					written).

	cont		cAA..AA		AA..AA is address to resume
					If AA..AA is omitted,
					resume at same address.

	step		sAA..AA		AA..AA is address to resume
					If AA..AA is omitted,
					resume at same address.

	last signal     ?               Reply the current reason for stopping.
                                        This is the same reply as is generated
					for step or cont : SAA where AA is the
					signal number.

	There is no immediate reply to step or cont.
	The reply comes when the machine stops.
	It is		SAA		AA is the "signal number"

	or...		TAAn...:r...;n:r...;n...:r...;
					AA = signal number
					n... = register number
					r... = register contents
	or...		WAA		The process exited, and AA is
					the exit status.  This is only
					applicable for certains sorts of
					targets.
	kill request	k

	toggle debug	d		toggle debug flag (see 386 & 68k stubs)
	reset		r		reset -- see sparc stub.
	reserved	<other>		On other requests, the stub should
					ignore the request and send an empty
					response ($#<checksum>).  This way
					we can extend the protocol and GDB
					can tell whether the stub it is
					talking to uses the old or the new.
	search		tAA:PP,MM	Search backwards starting at address
					AA for a match with pattern PP and
					mask MM.  PP and MM are 4 bytes.
					Not supported by all stubs.

	general query	qXXXX		Request info about XXXX.
	general set	QXXXX=yyyy	Set value of XXXX to yyyy.
	query sect offs	qOffsets	Get section offsets.  Reply is
					Text=xxx;Data=yyy;Bss=zzz
	console output	Otext		Send text to stdout.  Only comes from
					remote target.

	Responses can be run-length encoded to save space.  A '*' means that
	the next character is an ASCII encoding giving a repeat count which
	stands for that many repititions of the character preceding the '*'.
	The encoding is n+29, yielding a printable character where n >=3 
	(which is where rle starts to win).  Don't use an n > 126. 

	So 
	"0* " means the same as "0000".  */

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>

#define __set_errno(val) errno = (val)

/*
 * BUFMAX defines the maximum number of characters in inbound/outbound
 * buffers. At least NUMREGBYTES*2 are needed for register packets.
 */
#define BUFMAX 1024

/*
 * Number of bytes for registers
 */
#define NUMREGBYTES (24*4+8*8)		/* 160 */

/*
 * typedef
 */
typedef void (*Function) ();

/*
 * Forward declarations
 */

static int hex (char);
static char *mem2hex (char *, char *, int);
static char *hex2mem (char *, char *, int);
static int hexToInt (char **, int *);
static char *getpacket (void);
static void putpacket (char *);
static int computeSignal (int exceptionVector);
static void handle_exception (int exceptionVector);
void init_serial();

void putDebugChar (char);
char getDebugChar (void);

int breakpoint (void *);


int *registers;
static const char hexchars[] = "0123456789abcdef";
static char remcomInBuffer[BUFMAX];
static char remcomOutBuffer[BUFMAX];

char highhex(int  x)
{
  return hexchars[(x >> 4) & 0xf];
}

char lowhex(int  x)
{
  return hexchars[x & 0xf];
}

/*
 * Routines to handle hex data
 */

static int
hex (char ch)
{
  if ((ch >= 'a') && (ch <= 'f'))
    return (ch - 'a' + 10);
  if ((ch >= '0') && (ch <= '9'))
    return (ch - '0');
  if ((ch >= 'A') && (ch <= 'F'))
    return (ch - 'A' + 10);
  return (-1);
}

/* convert the memory, pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
static char *
mem2hex (char *mem, char *buf, int count)
{
  int i;
  int ch;
  for (i = 0; i < count; i++)
    {
      ch = *mem++;
      *buf++ = highhex (ch);
      *buf++ = lowhex (ch);
    }
  *buf = 0;
  return (buf);
}

/* convert the hex array pointed to by buf into binary, to be placed in mem */
/* return a pointer to the character after the last byte written */

static char *
hex2mem (char *buf, char *mem, int count)
{
  int i;
  unsigned char ch;
  for (i = 0; i < count; i++)
    {
      ch = hex (*buf++) << 4;
      ch = ch + hex (*buf++);
      *mem++ = ch;
    }
  return (mem);
}

/**********************************************/
/* WHILE WE FIND NICE HEX CHARS, BUILD AN INT */
/* RETURN NUMBER OF CHARS PROCESSED           */
/**********************************************/
static int
hexToInt (char **ptr, int *intValue)
{
  int numChars = 0;
  int hexValue;

  *intValue = 0;

  while (**ptr)
    {
      hexValue = hex (**ptr);
      if (hexValue >= 0)
	{
	  *intValue = (*intValue << 4) | hexValue;
	  numChars++;
	}
      else
	break;

      (*ptr)++;
    }

  return (numChars);
}

/*
 * Routines to get and put packets
 */

/* scan for the sequence $<data>#<checksum>     */

char *
getpacket (void)
{
  char *buffer = &remcomInBuffer[0];
  unsigned char checksum;
  unsigned char xmitcsum;
  int count;
  char ch;

  while (1)
    {
      /* wait around for the start character, ignore all other characters */
      while ((ch = getDebugChar ()) != '$')
	;

retry:
      checksum = 0;
      xmitcsum = -1;
      count = 0;

      /* now, read until a # or end of buffer is found */
      while (count < BUFMAX - 1)
	{
	  ch = getDebugChar ();
          if (ch == '$')
            goto retry;
	  if (ch == '#')
	    break;
	  checksum = checksum + ch;
	  buffer[count] = ch;
	  count = count + 1;
	}
      buffer[count] = 0;

      if (ch == '#')
	{
 	  ch = getDebugChar ();
 	  xmitcsum = hex (ch) << 4;
 	  ch = getDebugChar ();
 	  xmitcsum += hex (ch);

	  if (checksum != xmitcsum)
	    {
	      putDebugChar ('-');	/* failed checksum */
	    }
	  else
	    {
	      putDebugChar ('+');	/* successful transfer */

	      /* if a sequence char is present, reply the sequence ID */
	      if (buffer[2] == ':')
		{
		  putDebugChar (buffer[0]);
		  putDebugChar (buffer[1]);

 		  return &buffer[3];
		}

	      return &buffer[0];
	    }
	}
    }
}


/* send the packet in buffer. */

static void
putpacket (char *buffer)
{
  int checksum;
  int count;

  /*  $<packet info>#<checksum>. */
  do
    {
      char *src = buffer;
      putDebugChar ('$');
      checksum = 0;

      while (*src)
	{
	  int runlen;

	  /* Do run length encoding */
	  for (runlen = 0; runlen < 100; runlen ++) 
	    {
	      if (src[0] != src[runlen] || runlen == 99) 
		{
		  if (runlen > 3) 
		    {
		      int encode;
		      /* Got a useful amount */
		      putDebugChar (*src);
		      checksum += *src;
		      putDebugChar ('*');
		      checksum += '*';
		      checksum += (encode = runlen + ' ' - 4);
		      putDebugChar (encode);
		      src += runlen;
		    }
		  else
		    {
		      putDebugChar (*src);
		      checksum += *src;
		      src++;
		    }
		  break;
		}
	    }
	}


      putDebugChar ('#');
      putDebugChar (highhex(checksum));
      putDebugChar (lowhex(checksum));
    }
  while  (getDebugChar() != '+');
}

/*
This function does all exception handling.  It only does two things -
it figures out why it was called and tells gdb, and then it reacts
to gdb's requests.

When in the monitor mode we talk a human on the serial line rather than gdb.

*/

struct fcall {
  char command[512];
  int retval;
  int __errno;
  int breakflag;
};

struct fcall gdbstub_fcall;

typedef int gdbmode_t;
typedef int gdbtime_t;

struct gdbstat {
  unsigned int st_dev;
  unsigned int st_ino;
  gdbmode_t st_mode;
  unsigned int st_nlink;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned int st_rdev;
  unsigned long long st_size;
  unsigned long long st_blksize;
  unsigned long long st_blocks;
  gdbtime_t __st_atime;
  gdbtime_t __st_mtime;
  gdbtime_t __st_ctime;
};

static int __gdb_syscall(void);

#define GDB_O_RDONLY 0
#define GDB_O_WRONLY 1
#define GDB_O_RDWR 2
#define GDB_O_APPEND 8
#define GDB_O_CREAT 0x200
#define GDB_O_TRUNC 0x400
#define GDB_O_EXCL 0x800

#define GDB_S_IFREG       0100000
#define GDB_S_IFDIR        040000
#define GDB_S_IRUSR          0400
#define GDB_S_IWUSR          0200
#define GDB_S_IXUSR          0100
#define GDB_S_IRGRP           040
#define GDB_S_IWGRP           020
#define GDB_S_IXGRP           010
#define GDB_S_IROTH            04
#define GDB_S_IWOTH            02
#define GDB_S_IXOTH            01

#define GDB_EPERM           1
#define GDB_ENOENT          2
#define GDB_EINTR           4
#define GDB_EBADF           9
#define GDB_EACCES         13
#define GDB_EFAULT         14
#define GDB_EBUSY          16
#define GDB_EEXIST         17
#define GDB_ENODEV         19
#define GDB_ENOTDIR        20
#define GDB_EISDIR         21
#define GDB_EINVAL         22
#define GDB_ENFILE         23
#define GDB_EMFILE         24
#define GDB_EFBIG          27
#define GDB_ENOSPC         28
#define GDB_ESPIPE         29
#define GDB_EROFS          30
#define GDB_ENAMETOOLONG   91
#define GDB_EUNKNOWN       9999

#define GDB_SEEK_SET      0
#define GDB_SEEK_CUR      1
#define GDB_SEEK_END      2

int
__gdb_errno(int gdberrno)
{
  switch (gdberrno) {
  case GDB_EPERM: return EPERM;
  case GDB_ENOENT: return ENOENT;
  case GDB_EINTR: return EINTR;
  case GDB_EBADF: return EBADF;
  case GDB_EACCES: return EACCES;
  case GDB_EFAULT: return EFAULT;
  case GDB_EBUSY: return EBUSY;
  case GDB_EEXIST: return EEXIST;
  case GDB_ENODEV: return ENODEV;
  case GDB_ENOTDIR: return ENOTDIR;
  case GDB_EISDIR: return EISDIR;
  case GDB_EINVAL: return EINVAL;
  case GDB_ENFILE: return ENFILE;
  case GDB_EMFILE: return EMFILE;
  case GDB_EFBIG: return EFBIG;
  case GDB_ENOSPC: return ENOSPC;
  case GDB_ESPIPE: return ESPIPE;
  case GDB_EROFS: return EROFS;
  case GDB_ENAMETOOLONG: return ENAMETOOLONG;
  case GDB_EUNKNOWN: return EINVAL;
  }

  return EINVAL;
}

int
__gdb_flags(int flags)
{
  int gdbflags = 0;

  if ((flags&3) == O_RDONLY)
    gdbflags = GDB_O_RDONLY;
  if ((flags&3) == O_WRONLY)
    gdbflags = GDB_O_WRONLY;
  if ((flags&3) == O_RDWR)
    gdbflags = GDB_O_RDWR;

  if (flags & O_APPEND)
    gdbflags |= GDB_O_APPEND;
  if (flags & O_CREAT)
    gdbflags |= GDB_O_CREAT;
  if (flags & O_TRUNC)
    gdbflags |= GDB_O_TRUNC;
  if (flags & O_EXCL)
    gdbflags |= GDB_O_EXCL;

  return gdbflags;
}

int
__gdb_rflags(int gdbflags)
{
  int flags = 0;

  if ((gdbflags&3) == GDB_O_RDONLY)
    flags = O_RDONLY;
  if ((gdbflags&3) == GDB_O_WRONLY)
    flags = O_WRONLY;
  if ((gdbflags&3) == GDB_O_RDWR)
    flags = O_RDWR;

  if (gdbflags & GDB_O_APPEND)
    flags |= O_APPEND;
  if (gdbflags & GDB_O_CREAT)
    flags |= O_CREAT;
  if (gdbflags & GDB_O_TRUNC)
    flags |= O_TRUNC;
  if (gdbflags & GDB_O_EXCL)
    flags |= O_EXCL;

  return flags;
}

gdbmode_t
__gdb_mode(mode_t mode)
{
  gdbmode_t gdbmode = mode & 0777;

  if (mode & S_IFREG)
    gdbmode |= GDB_S_IFREG;
  if (mode & S_IFDIR)
    gdbmode |= GDB_S_IFDIR;

  return gdbmode;
}

gdbmode_t
__gdb_rmode(gdbmode_t gdbmode)
{
  mode_t mode = gdbmode & 0777;

  if (gdbmode & GDB_S_IFREG)
    mode |= S_IFREG;
  if (gdbmode & GDB_S_IFDIR)
    mode |= S_IFDIR;

  return mode;
}

void
gdb_handle_exception (int exceptionVector)
{
}

int
__gdb_open(const char *pathname, int flags, int mode)
{
  snprintf(gdbstub_fcall.command, 510, "Fopen,%x/%x,%x,%x",
	   (int)pathname, (int)strlen(pathname)+1,
	   (int)__gdb_flags(flags), (int)__gdb_mode(mode));

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_close(int fd)
{
  snprintf(gdbstub_fcall.command, 510, "Fclose,%x",
	   fd);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;


  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_read(int fd, void *buf, unsigned int count)
{
  snprintf(gdbstub_fcall.command, 510, "Fread,%x,%x,%x",
	   fd, (int)buf, count);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_write(int fd, void *buf, unsigned int count)
{
  snprintf(gdbstub_fcall.command, 510, "Fwrite,%x,%x,%x",
	   fd, (int)buf, count);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_lseek(int fd, long offset, int whence)
{
  int gdbwhence;

  switch (whence) {
  case SEEK_SET: gdbwhence = GDB_SEEK_SET;
  default:
  case SEEK_CUR: gdbwhence = GDB_SEEK_CUR;
  case SEEK_END: gdbwhence = GDB_SEEK_END;
  }

  snprintf(gdbstub_fcall.command, 510, "Flseek,%x,%x,%x",
	   fd, (int)offset, gdbwhence);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_rename(const char *oldpath, const char *newpath)
{
  snprintf(gdbstub_fcall.command, 510, "Frename,%x/%x,%x/%x",
	   (int)oldpath, strlen(oldpath)+1,
	   (int)newpath, strlen(newpath)+1);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_unlink(const char *path)
{
  snprintf(gdbstub_fcall.command, 510, "Funlink,%x/%x",
	   (int)path, strlen(path)+1);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}
int
__gdb_stat(const char *path, struct stat *buf)
{
  struct gdbstat gdbbuf;
  snprintf(gdbstub_fcall.command, 510, "Fstat,%x/%x,%x",
	   (int)path, strlen(path)+1, (int)&gdbbuf);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  } else {
    buf->st_dev = gdbbuf.st_dev;
    buf->st_ino = gdbbuf.st_ino;
    buf->st_mode = __gdb_rmode(gdbbuf.st_mode);
    buf->st_nlink = gdbbuf.st_nlink;
    buf->st_uid = gdbbuf.st_uid;
    buf->st_gid = gdbbuf.st_gid;
    buf->st_rdev = gdbbuf.st_rdev;
    buf->st_size = gdbbuf.st_size;
    buf->st_blksize = gdbbuf.st_blksize;
    buf->st_blocks = gdbbuf.st_blocks;
    buf->st_atime = gdbbuf.__st_atime;
    buf->st_mtime = gdbbuf.__st_mtime;
    buf->st_ctime = gdbbuf.__st_ctime;
  }

  return gdbstub_fcall.retval;
}

int
__gdb_fstat(int fd, struct stat *buf)
{
  struct gdbstat gdbbuf;

  snprintf(gdbstub_fcall.command, 510, "Ffstat,%x,%x",
	   fd, (int)&gdbbuf);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  } else {
    buf->st_dev = gdbbuf.st_dev;
    buf->st_ino = gdbbuf.st_ino;
    buf->st_mode = __gdb_rmode(gdbbuf.st_mode);
    buf->st_nlink = gdbbuf.st_nlink;
    buf->st_uid = gdbbuf.st_uid;
    buf->st_gid = gdbbuf.st_gid;
    buf->st_rdev = gdbbuf.st_rdev;
    buf->st_size = gdbbuf.st_size;
    buf->st_blksize = gdbbuf.st_blksize;
    buf->st_blocks = gdbbuf.st_blocks;
    buf->st_atime = gdbbuf.__st_atime;
    buf->st_mtime = gdbbuf.__st_mtime;
    buf->st_ctime = gdbbuf.__st_ctime;
  }

  return gdbstub_fcall.retval;
}

struct gdbtimeval {
  time_t tv_sec;
  long long tv_usec;
};

int
__gdb_gettimeofday(struct timeval *tv, void *tz)
{
  struct gdbtimeval gdbtv;
  snprintf(gdbstub_fcall.command, 510, "Fgettimeofday,%x,%x",
	   (int)&gdbtv, (int)tz);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  } else {
    tv->tv_sec = gdbtv.tv_sec;
    tv->tv_usec = gdbtv.tv_usec;
  }

  return gdbstub_fcall.retval;
}

int
__gdb_isatty(int fd)
{
  snprintf(gdbstub_fcall.command, 510, "Fisatty,%x",
	   fd);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_system(const char *command)
{
  snprintf(gdbstub_fcall.command, 510, "Fsystem,%x/%x",
	   (int)command, strlen(command)+1);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

int
__gdb_chdir(const char *path)
{
  snprintf(gdbstub_fcall.command, 510, "Fchdir,%x/%x",
	   (int)path, strlen(path)+1);

  gdbstub_fcall.retval = 0;
  gdbstub_fcall.__errno = 0;
  gdbstub_fcall.breakflag = 0;

  gdb_handle_exception(0);

  if (gdbstub_fcall.retval < 0) {
    __set_errno(__gdb_errno(gdbstub_fcall.__errno));
  }

  return gdbstub_fcall.retval;
}

void
gdbstub_main(struct wasm32_registers *regs, int sigval)
{
  int stepping;
  int addr, length;
  char *ptr;
  static int stopped = 0;

  if (gdbstub_fcall.command[0]) {
    snprintf(remcomOutBuffer, BUFMAX, gdbstub_fcall.command);
    stopped = 0;
  } else {
    /* reply to host that an exception has occurred */
    remcomOutBuffer[0] = 'S';
    remcomOutBuffer[1] = highhex(sigval);
    remcomOutBuffer[2] = lowhex (sigval);
    remcomOutBuffer[3] = 0;
  }

  if (!stopped) {
    putpacket (remcomOutBuffer);
    stopped = 1;
  }

  stepping = 0;

  while (1)
    {
      remcomOutBuffer[0] = 0;
      ptr = getpacket ();

      switch (*ptr++)
	{
	case '?':
	  remcomOutBuffer[0] = 'S';
	  remcomOutBuffer[1] = highhex (sigval);
	  remcomOutBuffer[2] = lowhex (sigval);
	  remcomOutBuffer[3] = 0;
	  break;
	case 'F': {
	  int sign = 1;
	  ((*ptr != '-' || (ptr++, sign = -1)) &&
	   hexToInt (&ptr, &gdbstub_fcall.retval) &&
	   *ptr++ == ',' &&
	   hexToInt (&ptr, &gdbstub_fcall.__errno) &&
	   *ptr++ == ',' &&
	   hexToInt (&ptr, &gdbstub_fcall.breakflag));
	  gdbstub_fcall.retval *= sign;
	  return;
	}
	case 'g':		/* return the value of the CPU registers */
	  mem2hex ((char *) regs, remcomOutBuffer, NUMREGBYTES);
	  break;
	case 'G':		/* set the value of the CPU registers - return OK */
	  hex2mem (ptr, (char *) regs, NUMREGBYTES);
	  strcpy (remcomOutBuffer, "OK");
	  break;

	  /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
	case 'm':
	  if (1)
	    {
	      /* TRY, TO READ %x,%x.  IF SUCCEED, SET PTR = 0 */
	      if (hexToInt (&ptr, &addr))
		if (*(ptr++) == ',')
		  if (hexToInt (&ptr, &length))
		    {
		      ptr = 0;
		      mem2hex ((char *) addr, remcomOutBuffer, length);
		    }
	      if (ptr)
		strcpy (remcomOutBuffer, "E01");
	    }
	  else
	    strcpy (remcomOutBuffer, "E03");

	  /* restore handler for bus error */
	  break;

	  /* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
	case 'M':
	  if (1)
	    {
	      /* TRY, TO READ '%x,%x:'.  IF SUCCEED, SET PTR = 0 */
	      if (hexToInt (&ptr, &addr))
		if (*(ptr++) == ',')
		  if (hexToInt (&ptr, &length))
		    if (*(ptr++) == ':')
		      {
			hex2mem (ptr, (char *) addr, length);
			ptr = 0;
			strcpy (remcomOutBuffer, "OK");
		      }
	      if (ptr)
		strcpy (remcomOutBuffer, "E02");
	    }
	  else
	    strcpy (remcomOutBuffer, "E03");

	  break;

	  /* cAA..AA    Continue at address AA..AA(optional) */
	  /* sAA..AA   Step one instruction from AA..AA(optional) */
	case 's':
	case 'c':
	  return;
	  break;

	  /* kill the program */
	case 'k':		/* do nothing */
	  break;
	case 'Z':
#if 0
	  {
	  int addr;
	  int i;
	  if (*ptr++ != '1' ||
	      *ptr++ != ',' ||
	      !hexToInt (&ptr, &addr)) {
	    break;
	  }

	  addr >>= 4;

	  for (i = 0; i < GDBSTUB_BPS; i++) {
	    if (gdbstub_bps[i] == -1)
	      break;
	  }

	  /* no slot */
	  if (i == GDBSTUB_BPS)
	    break;

	  gdbstub_bps[i] = addr;
	  strcpy (remcomOutBuffer, "OK");
	  break;
	}
#else
	  break;
#endif
	case 'z':
#if 0
	  {
	  int addr;
	  int i, j;
	  if (*ptr++ != '1' ||
	      *ptr++ != ',' ||
	      !hexToInt (&ptr, &addr)) {
	    break;
	  }

	  addr >>= 4;

	  for (i = 0; i < GDBSTUB_BPS; i++) {
	    if (gdbstub_bps[i] == addr)
	      break;
	  }

	  /* not found */
	  if (i == GDBSTUB_BPS)
	    break;

	  gdbstub_bps[i] = -1;

	  for (j = GDBSTUB_BPS-1; j > i; j--) {
	    if (gdbstub_bps[j] != -1)
	      break;
	  }

	  if (j > i) {
	    gdbstub_bps[i] = gdbstub_bps[j];
	    gdbstub_bps[j] = -1;
	  }

	  strcpy (remcomOutBuffer, "OK");

	  break;
	}
#else
	  break;
	}
#endif
      /* reply to the request */
      putpacket (remcomOutBuffer);
    }
}

/* This function will generate a breakpoint exception.  It is used at the
   beginning of a program to sync up with a debugger and can be used
   otherwise as a quick means to stop program execution and "break" into
   the debugger. */

extern "C" {
  unsigned long gdbstub_entry(void *, unsigned long);
};

int
breakpoint (void *regp)
{
  registers = (int *)regp;
  gdbstub_entry(__builtin_frame_address(0), 0);
  return 0;
}

char 
getDebugChar (void)
{
  char ch;

  while (read_debug (&ch, 1) == 0)
    ; //wait_debug ();

  return ch;
}

void
putDebugChar (char ch)
{
  write_debug(&ch, 1);
}

int breakpoint2(void *regp) asm("breakpoint2");

int breakpoint2(void *regp)
{
  struct wasm32_registers regs;

  gdbstub_main (&regs, 5);
  return 0;
  //asm volatile("return (fp|0)+32+80;");
}

unsigned long gdbstub_inner(void *fp, unsigned long rv,
			    void *sp)
{
  struct wasm32_registers regs;

  memset(&regs, 0, sizeof regs);

  if (fp)
    unpack_registers(&regs, (unsigned long *)fp, rv);
  if (sp)
    unpack_registers(&regs, (unsigned long *)sp, regs.rv);

  gdbstub_main(&regs, 5);

  return regs.rv;
}

unsigned long gdbstub_entry(void *sp, unsigned long rv)
{
  volatile int dummy = 0;
  void *fp = __builtin_frame_address(0);
  static int in_bp  = 0;

  if (in_bp)
    return rv;

  in_bp++;

  if (dummy)
    __builtin_eh_return(0, 0);

  //asm volatile("HEAP32[%O0>>2] = a0|0;" : : "r" (fp + 16));
  //asm volatile("HEAP32[%O0>>2] = a1|0;" : : "r" (fp + 20));
  //asm volatile("HEAP32[%O0>>2] = a2|0;" : : "r" (fp + 24));
  //asm volatile("HEAP32[%O0>>2] = a3|0;" : : "r" (fp + 28));

  rv = gdbstub_inner(fp, rv, sp);

  //asm volatile("a0 = HEAP32[%O0>>2]|0;" : : "r" (fp + 16));
  //asm volatile("a1 = HEAP32[%O0>>2]|0;" : : "r" (fp + 20));
  //asm volatile("a2 = HEAP32[%O0>>2]|0;" : : "r" (fp + 24));
  //asm volatile("a3 = HEAP32[%O0>>2]|0;" : : "r" (fp + 28));

  in_bp--;

  return rv;
}

struct __GDBStub {
  bool running;
  __GDBStub()
  {
    if (false) {
      gdbstub_entry(__builtin_frame_address(0), 0);
      running = true;
    }
  }

  ~__GDBStub()
  {
    if (running)
      gdbstub_entry(__builtin_frame_address(0), 0);
  }
};

extern __GDBStub __gdbstub_ctor;

__GDBStub __gdbstub_ctor;
