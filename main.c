/*  This file is part of "sshpass", a tool for batch running password ssh authentication
 *  Copyright (C) 2006, 2015 Lingnu Open Source Consulting Ltd.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version, provided that it was accepted by
 *  Lingnu Open Source Consulting Ltd. as an acceptable license for its
 *  projects. Consult http://www.lingnu.com/licenses.html
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// comment by Clark::当main函数开始执行，主进程执行`masterpt=posix_openpt(O_RDWR);`此时会有一个伪终端，然后fork（）出一个子进程，在子进程下执行ssh命令，当收到带有*assword关键词的输出时候讲密码填充进去。  ::2021-3-27

#if HAVE_CONFIG_H
// comment by Clark:: 此 config.h 应该是在编译的过程中生成的  ::2021-3-27
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#if HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

enum program_return_codes {
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
};

// Some systems don't define posix_openpt
#ifndef HAVE_POSIX_OPENPT
int
posix_openpt(int flags)
{
    return open("/dev/ptmx", flags);
}
#endif

int runprogram( int argc, char *argv[] );

struct {
    enum { PWT_STDIN, PWT_FILE, PWT_FD, PWT_PASS } pwtype;
    union {
	const char *filename;
	int fd;
	const char *password;
    } pwsrc;

    const char *pwprompt;
    int verbose;
} args;

static void show_help()
{
    printf("Usage: " PACKAGE_NAME " [-f|-d|-p|-e] [-hV] command parameters\n"
	    "   -f filename   Take password to use from file\n"
	    "   -d number     Use number as file descriptor for getting password\n"
	    "   -p password   Provide password as argument (security unwise)\n"
	    "   -e            Password is passed as env-var \"SSHPASS\"\n"
	    "   With no parameters - password will be taken from stdin\n\n"
            "   -P prompt     Which string should sshpass search for to detect a password prompt\n"
            "   -v            Be verbose about what you're doing\n"
	    "   -h            Show help (this screen)\n"
	    "   -V            Print version information\n"
	    "At most one of -f, -d, -p or -e should be used\n");
}

// Parse the command line. Fill in the "args" global struct with the results. Return argv offset
// on success, and a negative number on failure
static int parse_options( int argc, char *argv[] )
{
    int error=-1;
    int opt;

    // Set the default password source to stdin
    args.pwtype=PWT_STDIN;
    args.pwsrc.fd=0;

#define VIRGIN_PWTYPE if( args.pwtype!=PWT_STDIN ) { \
    fprintf(stderr, "Conflicting password source\n"); \
    error=RETURN_CONFLICTING_ARGUMENTS; }

	// comment by Clark:: 后面有冒号的代表需要额外的参数  ::2021-3-27
	// comment by Clark:: 解析后的参数放在 optarg 中  ::2021-3-27
    while( (opt=getopt(argc, argv, "+f:d:p:P:heVv"))!=-1 && error==-1 ) {
	switch( opt ) {
	case 'f':
	    // Password should come from a file
	    VIRGIN_PWTYPE;
	    
	    args.pwtype=PWT_FILE;
	    args.pwsrc.filename=optarg;
	    break;
	case 'd':
	    // Password should come from an open file descriptor
	    VIRGIN_PWTYPE;

	    args.pwtype=PWT_FD;
	    args.pwsrc.fd=atoi(optarg);
	    break;
	case 'p':
	    // Password is given on the command line
	    VIRGIN_PWTYPE;

	    args.pwtype=PWT_PASS;
	    args.pwsrc.password=strdup(optarg);
            
            // Hide the original password from the command line
            {
                int i;

                for( i=0; optarg[i]!='\0'; ++i )
                    optarg[i]='z';
            }
	    break;
        case 'P':
        	// comment by Clark:: sshpass需要抓捕的提示, 提前预先得知               ::2021-3-27
            args.pwprompt=optarg;
            break;
        case 'v':
            args.verbose++;
            break;
	case 'e':
	    VIRGIN_PWTYPE;

	    args.pwtype=PWT_PASS;
	    args.pwsrc.password=getenv("SSHPASS");
            if( args.pwsrc.password==NULL ) {
                fprintf(stderr, "sshpass: -e option given but SSHPASS environment variable not set\n");

                error=RETURN_INVALID_ARGUMENTS;
            }
	    break;
	case '?':
	case ':':
	    error=RETURN_INVALID_ARGUMENTS;
	    break;
	case 'h':
	    error=RETURN_NOERROR;
	    break;
	case 'V':
	    printf("%s\n"
                    "(C) 2006-2011 Lingnu Open Source Consulting Ltd.\n"
                    "(C) 2015-2016 Shachar Shemesh\n"
		    "This program is free software, and can be distributed under the terms of the GPL\n"
		    "See the COPYING file for more information.\n"
                    "\n"
                    "Using \"%s\" as the default password prompt indicator.\n", PACKAGE_STRING, PASSWORD_PROMPT );
	    exit(0);
	    break;
	}
    }

    if( error>=0 )
	return -(error+1);
    else
	return optind;
}

int main( int argc, char *argv[] )
{
    int opt_offset=parse_options( argc, argv );

    if( opt_offset<0 ) {
	// There was some error
	show_help();

        return -(opt_offset+1); // -1 becomes 0, -2 becomes 1 etc.
    }

    if( argc-opt_offset<1 ) {
	show_help();

        return 0;
    }

    return runprogram( argc-opt_offset, argv+opt_offset );
}

int handleoutput( int fd );

/* Global variables so that this information be shared with the signal handler */
static int ourtty; // Our own tty
static int masterpt;

void window_resize_handler(int signum);
void sigchld_handler(int signum);

int runprogram( int argc, char *argv[] )
{
    struct winsize ttysize; // The size of our tty

    // We need to interrupt a select with a SIGCHLD. In order to do so, we need a SIGCHLD handler

    /*
    
    comment by Clark:: 
    	SIGCHLD，在一个进程终止或者停止时，将SIGCHLD信号发送给其父进程，按系统默认将忽略此信号,
    如果父进程希望被告知其子系统的这种状态，则应捕捉此信号.
    	SIGCHLD属于unix以及类unix系统的一种信号
		产生原因 						siginfo_t代码值
		1，子进程已终止 					CLD_EXITED
		2，子进程异常终止（无core） CLD_KILLED
		3，子进程异常终止（有core） CLD_DUMPED
		4，被跟踪子进程以陷入 				CLD_TRAPPED
		5，子进程已停止 					CLD_STOPED
		5，停止的子进程已经继续 				CLD_CONTINUED
		
   	::2021-3-27
   	*/ 
    
    signal( SIGCHLD,sigchld_handler );

    // Create a pseudo terminal for our process

    /* 
    	comment by Clark:: 
    	
    https://blog.csdn.net/luckywang1103/article/details/71191821
    
	ptmx,pts pseudo terminal master and slave
	ptmx 与 pts 配合实现pty(伪终端)
	
	在telnet，ssh等远程终端工具中会使用到 pty, 通常的数据流是这样的
	
	telnetd进程 ---> /dev/ptmx(master) ---> /dev/pts/?(slave) ---> getty
	telnetd进程收到网络中的数据后，将数据丢给ptmx，ptmx像管道一样将数据丢给pts/?, getty进程从 pts/? 读取数据传递给shell去执行.
	
	linux支持的两种pty
	a. UNIX98 pseudoterminal, 使用的是devpts文件系统，挂载在 /dev/pts目录
	b. 在UNIX98 pseudoterminal之前，master pseudoterminal 名字为 /dev/ptyp0,…，slave pseudoterminal名字为/dev/ttyp0,…，
	这个方法需要预先分配好很多的设备节点.
	
	只有在open /dev/ptmx程序不退出的情况下，/dev/pts/目录下才会有对应的设备节点
	在程序执行 "open /dev/ptmx" 的时候会在 /dev/pts/ 目录下生成一个设备节点, 比如0, 1…, 但是当程序退出的时候这个设备节点就消失了,
	可以通过如下一个例子演示在”open /dev/ptmx”的时候在/dev/pts目录下生成的设备节点

	$ ls /dev/pts; ls /dev/pts < /dev/ptmx
	0  1  2  ptmx
	0  1  2  3  ptmx


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>

int main()
{
        int fd_m, fd_s;
        int len;
        const char *pts_name;
        char send_buf[64] = "abc\ndefghijk\nlmn";
        char recv_buf[64] = {0};

        fd_m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (fd_m < 0) {
                printf("open /dev/ptmx fail\n");
                return -1;
        }

        if (grantpt(fd_m) < 0 || unlockpt(fd_m) < 0) {
                printf("grantpt and unlockpt fail\n");
                goto err;
        }

        pts_name = (const char *)ptsname(fd_m);
        fd_s = open(pts_name, O_RDONLY | O_NOCTTY);
        if (fd_s < 0) {
                printf("open /dev/ptmx fail\n");
                goto err;
        }

        len = write(fd_m, send_buf, strlen(send_buf));
        printf("write len=%d\n", len);

        len = read(fd_s, recv_buf, sizeof(recv_buf));
        printf("read len=%d, recv_buf=[%s]\n", len, recv_buf);

        len = read(fd_s, recv_buf, sizeof(recv_buf));
        printf("read len=%d, recv_buf=[%s]\n", len, recv_buf);

        close(fd_m);
        close(fd_s);
        return 0;

err:
        if (fd_m)
                close(fd_m);
        if (fd_s)
                close(fd_s);

        return -1;
}

	read只有遇到换行符’\n’的时候才会返回，否则遇不到的话一直阻塞在那里。

	每open /dev/ptmx就会得到一个新的文件描述符, 并且在/dev/pts/ 目录下生成一个与这个文件描述符对应的新的设备节点
	
	当进程 open "/dev/ptmx" 的时候, 获得了一个新的 pseudoterminal master(PTM)的文件描述符, 同时会在/dev/pts目录下自动生成一个新的
	pseudoterminal slave(PTS)设备.

	每次open “/dev/ptmx”会得到一个不同的PTM文件描述符(多次open会得到多个文件描述符), 并且有和这个PTM描述符关联的PTS。

	grantpt, unlockpt: 在每次打开pseudoterminal slave的时候, 必须传递对应的PTM的文件描述符. grantpt以获得权限, 然后调用unlockpt解锁
	
	ptsname: 将PTM的文件描述符作为参数，会得到该描述符对应的PTS的路径

	向PTM写的数据可以从PTS读出来，向PTS写的数据可以从PTM读出来。
	
    ::2021-3-27    
    */

    // comment by Clark:: 应用程序打开一个伪终端  ::2021-3-27
    masterpt=posix_openpt(O_RDWR);

    if( masterpt==-1 ) {
	perror("Failed to get a pseudo terminal");

	return RETURN_RUNTIME_ERROR;
    }
	
    fcntl(masterpt, F_SETFL, O_NONBLOCK);

	// comment by Clark:: grantpt 函数可以把从设备节点的用户 ID 设置为调用者的实际用户 ID，设置其组 ID 为一非指定值，通常是可以访问该终端设备的组。权限被设置为 0620，即对个体所有者是读/写，对组所有者是写。实现通常将 PTY 从设备的组所有者设置为 tty 组。把那些要对系统中所有活动端具有写权限的程序（如 wall(1)和 write(1)）的设置组 ID 设置为 tty 组，因为在 PTY 从设备上 tty 组的写权限是被允许的。::2021-3-27
    if( grantpt( masterpt )!=0 ) {
	perror("Failed to change pseudo terminal's permission");

	return RETURN_RUNTIME_ERROR;
    }

    // comment by Clark::   ::2021-3-27
    if( unlockpt( masterpt )!=0 ) {
	perror("Failed to unlock pseudo terminal");

	return RETURN_RUNTIME_ERROR;
    }


    /*
		comment by Clark:: 
		1、在shell下可以直接用$LINES和$COLUMNS两个变量，$LINES是屏幕高，$COLUMNS是屏幕宽，单位都是字符数。
		2、大多数UNIX系统都提供了一种功能，可以对当前终端窗口的大小进行跟踪，在窗口大小发生变化时，
		使内核通知前台进程组. 内核为每个终端和伪终端保存一个winsize结构:
		//其中struct winsize位于termios.h头文件内
		//具体位置vim /usr/include/asm-generic/termios.h
		
	Struct winsize 
	{
    	unsigned short ws_row;    // rows， in character
	    unsigned short ws_col;        // columns, in characters
    	unsigned short ws_xpixel;    // horizontal size, pixels (unused)
	    unsigned short ws_ypixel;    // vertical size, pixels (unused)
	};
	
	winsize的结构作用
	1. 用ioctl函数的 TIOCGWINSZ 命令可以取此结构的当前值。
	2. 用ioctl函数的 TIOCSWINSZ 命令可以将此结构的新值存放到内核中. 如果此新值与存放在内核中的当前值不同, 则向前台进程组发送SIGWINCH信号。
	3. 除了存放此结构的当前值以及在此值改变时产生一个信号以外， 内核对该结构不进行任何其他操作. 对结构中的值进行解释完全是应用程序的工作。
	4. 提供这种功能的目的是, 当窗口大小发生变化时通知应用程序 (例如, vi编辑器) 应用程序接到此信号后，它可以取窗口大小的新值，然后重绘屏幕。

	
	通过函数 ioctl(); 获得终端界面的参数
	

	//具体实现方法
		#include<stdio.h>
		#include<sys/types.h>
		#include<sys/ioctl.h>
		#include<unistd.h>
		#include<termios.h>

		int main()
		{
		    //定义winsize 结构体变量
		    struct winsize size;
		    //TIOCSWINSZ命令可以将此结构的新值存放到内核中
		    ioctl(STDIN_FILENO,TIOCGWINSZ,&size);
		    printf("%d\n",size.ws_col);
		    printf("%d\n",size.ws_row);
		    return 0;
		}
		
	 */ 



	 /*
	 	comment by Clark::   

	 	https://blog.csdn.net/wocao1226/article/details/21749143
	 	https://blog.csdn.net/lqxandroid2012/article/details/79196637

		/dev/tty 当前终端，任何tty[任何类型的终端设备]
		echo "hello" > /dev/tty 都会直接显示在当前的终端中

		tty命令: 使用tty命令可以确定当前的终端或者控制台
		
 		/dev/tty0代表当前虚拟控制台，而/dev/tty1等代表第一个虚拟控制台

		在linux系统中, 终端是一种字符型设备. 它有多种类型, 通常使用tty来简称各种类型的终端设备.
		linux系统中包含如下几类终端设备: 
		(1) 串行端口终端 (/dev/ttySn) 						也就是你所问的串口(/dev/ttyAMA0,/dev/ttyUSB0等)
		(2) 伪终端 		 (/dev/pty)            			如telnet,ssh等
	    (3) 控制台终端        (/dev/ttyn,/dev/console)		如计算机显示器等


		::2021-3-27
	 */ 
    ourtty=open("/dev/tty", 0);
    if( ourtty!=-1 && ioctl( ourtty, TIOCGWINSZ, &ttysize )==0 ) {
        signal(SIGWINCH, window_resize_handler);

        ioctl( masterpt, TIOCSWINSZ, &ttysize );
    }

	// comment by Clark:: ptsname() -- 获得从伪终端名(slave pseudo-terminal)  ::2021-3-27
	// comment by Clark:: 伪终端并不是真正的硬件终端设备，而是一个应用程序。打开一个终端，输入tty 这个命令来查看当前所使用的终端名：  ::2021-3-27

	/* 
		comment by Clark::   
	
		zhang@zhang-laptop:~$ tty
		/dev/pts/1

		后面的1意味着已经打开了1个终端窗口。实际上，像上面的 /dev/pts/1是从伪终端,
		它通过文件 /dev/ptmx 建立。/dev/ptmx 可以建立主从伪终端,
		当打开该文件时，返回的是主伪终端的文件描述符，同时也会在 /dev/pts/ 目录下建立相应的从伪终端文件,
		如 /dev/pts/1 , /dev/pts/2 等. 更多关于主伪终端和从伪终端的信息可使用 man 4 ptmx 进行查阅

	::2021-3-27
	*/
    const char *name=ptsname(masterpt);
    int slavept;
    /*
       Comment no. 3.14159

       This comment documents the history of code.

       We need to open the slavept inside the child process, after "setsid", so that it becomes the controlling
       TTY for the process. We do not, otherwise, need the file descriptor open. The original approach was to
       close the fd immediately after, as it is no longer needed.

       It turns out that (at least) the Linux kernel considers a master ptty fd that has no open slave fds
       to be unused, and causes "select" to return with "error on fd". The subsequent read would fail, causing us
       to go into an infinite loop. This is a bug in the kernel, as the fact that a master ptty fd has no slaves
       is not a permenant problem. As long as processes exist that have the slave end as their controlling TTYs,
       new slave fds can be created by opening /dev/tty, which is exactly what ssh is, in fact, doing.

       Our attempt at solving this problem, then, was to have the child process not close its end of the slave
       ptty fd. We do, essentially, leak this fd, but this was a small price to pay. This worked great up until
       openssh version 5.6.

       Openssh version 5.6 looks at all of its open file descriptors, and closes any that it does not know what
       they are for. While entirely within its prerogative, this breaks our fix, causing sshpass to either
       hang, or do the infinite loop again.

       Our solution is to keep the slave end open in both parent AND child, at least until the handshake is
       complete, at which point we no longer need to monitor the TTY anyways.
     */

    int childpid=fork();
    if( childpid==0 ) {
	// Child

	// comment by Clark:: setsid后子进程不受终端影响, 终端退出, 不影响子进程  ::2021-3-27
	// Detach us from the current TTY
	setsid();
	
    // This line makes the ptty our controlling tty. We do not otherwise need it open
    slavept=open(name, O_RDWR );
    close( slavept );
	
	close( masterpt );

	char **new_argv=malloc(sizeof(char *)*(argc+1));

	int i;

	for( i=0; i<argc; ++i ) {
	    new_argv[i]=argv[i];
	}

	new_argv[i]=NULL;

	execvp( new_argv[0], new_argv );

	perror("sshpass: Failed to run command");

	exit(RETURN_RUNTIME_ERROR);
    } else if( childpid<0 ) {
	perror("sshpass: Failed to create child process");

	return RETURN_RUNTIME_ERROR;
    }
	
    // comment by Clark:: 打开这个是干嘛, 父进程打开伪从终端做什么???  ::2021-3-27
    // We are the parent
    slavept=open(name, O_RDWR|O_NOCTTY );

    int status=0;
    int terminate=0;
    pid_t wait_id;
    sigset_t sigmask, sigmask_select;

    // Set the signal mask during the select
    sigemptyset(&sigmask_select);

    // And during the regular run
    sigemptyset(&sigmask);
    
    // comment by Clark::  抓住这个消息 ::2021-3-27
    sigaddset(&sigmask, SIGCHLD);

	// comment by Clark::   ::2021-3-27
    sigprocmask( SIG_SETMASK, &sigmask, NULL );

    do {
	if( !terminate ) {
	    fd_set readfd;

	    FD_ZERO(&readfd);
	    FD_SET(masterpt, &readfd);

	    int selret=pselect( masterpt+1, &readfd, NULL, NULL, NULL, &sigmask_select );

	    if( selret>0 ) {
		if( FD_ISSET( masterpt, &readfd ) ) {
                    int ret;

            // comment by Clark:: 输入密码提示符是从哪里打印出来显示到终端上的                  ::2021-3-27
		    if( (ret=handleoutput( masterpt )) ) {
			// Authentication failed or any other error

                        // handleoutput returns positive error number in case of some error, and a negative value
                        // if all that happened is that the slave end of the pt is closed.
                        if( ret>0 ) {
                            close( masterpt ); // Signal ssh that it's controlling TTY is now closed
                            close(slavept);
                        }

			terminate=ret;

                        if( terminate ) {
                            close( slavept );
                        }
		    }
		}
	    }
	    wait_id=waitpid( childpid, &status, WNOHANG );
	} else {
	    wait_id=waitpid( childpid, &status, 0 );
	}
    } while( wait_id==0 || (!WIFEXITED( status ) && !WIFSIGNALED( status )) );

    if( terminate>0 )
	return terminate;
    else if( WIFEXITED( status ) )
	return WEXITSTATUS(status);
    else
	return 255;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state );
void write_pass( int fd );

int handleoutput( int fd )
{
    // We are looking for the string
    static int prevmatch=0; // If the "password" prompt is repeated, we have the wrong password.
    static int state1, state2;
    static int firsttime = 1;
    static const char *compare1=PASSWORD_PROMPT; // Asking for a password
    static const char compare2[]="The authenticity of host "; // Asks to authenticate host
    // static const char compare3[]="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"; // Warns about man in the middle attack
    // The remote identification changed error is sent to stderr, not the tty, so we do not handle it.
    // This is not a problem, as ssh exists immediately in such a case
    char buffer[256];
    int ret=0;

    if( args.pwprompt ) {
        compare1 = args.pwprompt;
    }

    if( args.verbose && firsttime ) {
        firsttime=0;
        fprintf(stderr, "SSHPASS searching for password prompt using match \"%s\"\n", compare1);
    }

    int numread=read(fd, buffer, sizeof(buffer)-1 );
    buffer[numread] = '\0';
    if( args.verbose ) {
        fprintf(stderr, "SSHPASS read: %s\n", buffer);
    }

    state1=match( compare1, buffer, numread, state1 );

    // Are we at a password prompt?
    if( compare1[state1]=='\0' ) {
	if( !prevmatch ) {
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected prompt. Sending password.\n");
	    write_pass( fd );
	    state1=0;
	    prevmatch=1;
	} else {
	    // Wrong password - terminate with proper error code
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected prompt, again. Wrong password. Terminating.\n");
	    ret=RETURN_INCORRECT_PASSWORD;
	}
    }

    if( ret==0 ) {
        state2=match( compare2, buffer, numread, state2 );

        // Are we being prompted to authenticate the host?
        if( compare2[state2]=='\0' ) {
            if( args.verbose )
                fprintf(stderr, "SSHPASS detected host authentication prompt. Exiting.\n");
            ret=RETURN_HOST_KEY_UNKNOWN;
        }
    }

    return ret;
}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state )
{
    // This is a highly simplisic implementation. It's good enough for matching "Password: ", though.
    int i;
    for( i=0;reference[state]!='\0' && i<bufsize; ++i ) {
	if( reference[state]==buffer[i] )
	    state++;
	else {
	    state=0;
	    if( reference[state]==buffer[i] )
		state++;
	}
    }

    return state;
}

void write_pass_fd( int srcfd, int dstfd );

void write_pass( int fd )
{
    switch( args.pwtype ) {
    case PWT_STDIN:
	write_pass_fd( STDIN_FILENO, fd );
	break;
    case PWT_FD:
	write_pass_fd( args.pwsrc.fd, fd );
	break;
    case PWT_FILE:
	{
	    int srcfd=open( args.pwsrc.filename, O_RDONLY );
	    if( srcfd!=-1 ) {
		write_pass_fd( srcfd, fd );
		close( srcfd );
	    }
	}
	break;
    case PWT_PASS:
	write( fd, args.pwsrc.password, strlen( args.pwsrc.password ) );
	write( fd, "\n", 1 );
	break;
    }
}

void write_pass_fd( int srcfd, int dstfd )
{

    int done=0;

    while( !done ) {
	char buffer[40];
	int i;
	int numread=read( srcfd, buffer, sizeof(buffer) );
	done=(numread<1);
	for( i=0; i<numread && !done; ++i ) {
	    if( buffer[i]!='\n' )
		write( dstfd, buffer+i, 1 );
	    else
		done=1;
	}
    }

    write( dstfd, "\n", 1 );
}

void window_resize_handler(int signum)
{
    struct winsize ttysize; // The size of our tty

    if( ioctl( ourtty, TIOCGWINSZ, &ttysize )==0 )
        ioctl( masterpt, TIOCSWINSZ, &ttysize );
}

// Do nothing handler - makes sure the select will terminate if the signal arrives, though.
void sigchld_handler(int signum)
{
}
