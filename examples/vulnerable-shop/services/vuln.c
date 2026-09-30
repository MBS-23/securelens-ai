#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int table[10];

void greet(const char *name) {
    char buf[16];
    strcpy(buf, name);
    printf(name);
}

int main(int argc, char *argv[]) {
    char line[64];
    char *p = malloc(32);
    greet(argv[1]);
    fgets(line, sizeof line, stdin);
    system(line);
    int idx = atoi(argv[2]);
    table[idx] = 1;
    free(p);
    strcpy(p, "x");
    free(p);
    size_t n = atoi(argv[3]);
    char *big = malloc(n * sizeof(int));
    gets(line);
    char word[16];
    scanf("%s", word);
    if (access(argv[4], W_OK) == 0) {
        FILE *f = fopen(argv[4], "w");
        fclose(f);
    }
    return 0;
}
