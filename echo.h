#ifndef ECHO_H
#define ECHO_H

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>

void SetEcho(bool echo)
{
	struct termios ttystate;

	//get the terminal state
	tcgetattr(STDIN_FILENO, &ttystate);
	if(!echo)
	{
		//turn echo off
		ttystate.c_lflag &= ~ECHO;
	}
	else if(echo)
	{
		//turn echo on
		ttystate.c_lflag |= ECHO;
	}
	//set the terminal attributes.
	tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}
#endif