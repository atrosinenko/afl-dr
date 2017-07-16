#include <stdio.h>

volatile int *ptr = NULL;
const char cmd[] = "NULL";

// Beware of compiler optimizations

int main(int argc, char *argv[]) {
    char buf[16];

    fgets(buf, sizeof buf, stdin);

    for (int i = 0; i < sizeof cmd - 1; ++i) {
        if (buf[i] != cmd[i])
            return 0;
    }

    *ptr = 1;

    return 0;
}
