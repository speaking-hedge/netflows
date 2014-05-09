#ifndef __PP_H
#define __PP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <getopt.h>

#define PPVERSION "0.1"

int check_file(char *name);

void usage(void);
void version(void);

#endif /* __PP_H */



