/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <stdio.h>

// Return the biggest set bite position
static inline int biggest_bit_index(int n) {
    int cnt = 0;
    while(n) {
        ++cnt;
        n>>= 1;
    }
    
    return cnt;
}

int main()
{
    int a[50] = { 1,3,5,7,9,11,13,15,17, 19};
                //0 1 2 3 4 5  6  7   8  9
    int pos = 0;
    // 9 = 1 0 0 1
    int tries = biggest_bit_index(9) - 1;
    int length = 9;
    int x  = -1;
    int set = 0;

    while(tries >= 0) {
        if(a[pos + (1 << tries)] == x) {
            pos = pos + (1 << tries);
            set = 1;
            break;
        }
        
        if(a[pos + (1 << tries)] < x) {
            if(!(pos + (1 << tries) > length))
                pos = pos + (1 << tries);
            --tries;
            continue;
        }
        
        if(a[pos + (1<<tries)] > x) {
            --tries;
            continue;
        }
    }
    
    if(set == 0)
        pos = -1;
    printf("%d", pos);
    
    return 0;
}
