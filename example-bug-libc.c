#include <stdio.h>
#include <string.h>

#include "afl-annotations.h"

volatile int *ptr = NULL;
const char cmd[] = "NULL";

// Beware of compiler optimizations

int main(int argc, char *argv[]) {
    char buf[16];

    RUN_FORKSERVER();

    fgets(buf, sizeof buf, stdin);

    if (strncmp(buf, cmd, 4)) {
        return 0;
    }

    *ptr = 1;

    return 0;
}
