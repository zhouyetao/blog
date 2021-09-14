#include<stdio.h>
void main()
{
    char buf[5] = "12345";
    write(1,buf,5);
    printf("\n");
}