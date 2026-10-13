#include "stdafx.h"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: hw2.exe <hostname-or-IP> <DNS-server-IP>");
        return 1;
    }
    printf("Lookup  : %s\n", argv[1]);
    printf("Server  : %s\n", argv[2]);
    if (inet_addr(argv[1]) != INADDR_NONE) {
		printf("Is IP address\n");
    }
    else {
		printf("Is hostname\n");
    }
    return 0;
}