#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
	char buf[100];
	setbuf(stdin, buf);
	read(0, buf, 0x100);
}

int main()
{
	char buf[100] = "Welcome to CTF!\n";
	setbuf(stdout, buf);
	write(1, buf, strlen(buf));
	vuln();
	return 0;
}
