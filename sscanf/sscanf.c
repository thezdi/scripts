
#include <stdio.h>

void sscanf_safe1(char *buf) {
    char s[20];
    int i;
    double d;
    int ret;

    ret = sscanf(buf, "%d %lf %s", &i, &d, s);
    if (ret != 3) {
        printf("Failure");
    }
    else {
        printf("d: %lf", d);
        printf("i: %d", i);
        printf("s: %s", s);
    }
}

void sscanf_vuln1(char *buf) {
    char s[20];
    int i;
    double d;

    sscanf(buf, "%d %lf %s", &i, &d, s);
    printf("d: %lf", d);
    printf("i: %d", i);
    printf("s: %s", s);
}

void sscanf_vuln2(char *buf) {
    char s[20];
    int i;
    double d;

    if (sscanf(buf, "%d %lf %s", &i, &d, s)) {
        printf("d: %lf", d);
        printf("i: %d", i);
        printf("s: %s", s);
    }
    else {
        printf("Failure");
    }
}

int main(int argc, char **argv) {
    if (argc == 2) {
        sscanf_safe1(argv[2]);
        sscanf_vuln1(argv[2]);
        sscanf_vuln2(argv[2]);
    }
    else {
        printf("Usage: %s teststring", argv[0]);
    }
}
