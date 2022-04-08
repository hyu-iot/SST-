#include <stdio.h>

#define max 5

int matrix[max][max];
int b[max][max];
int c[max][max] = { {1, 0, 0, 0, 0},
                    {0, 1, 0, 0, 0},
                    {0, 0, 1, 0, 0},
                    {0, 0, 0, 1, 0},
                    {0, 0, 0, 0, 1} };
int N;

void MakeMat()
{
    int size = N*N;
    for(int i =0;i<N;i++)
    {
        for(int j =0 ; j<N ; j++)
        {
            scanf("%d", &matrix[i][j]);
            b[i][j] = matrix[i][j];
        }
        getchar();
    }
}

void MatMul(int matrix[][max], int b[][max], int c[][max])
{
    int d[max][max];  
    for(int i=0; i<N;i++)
    {
        for(int j=0;j<N;j++)
        {   
            int sum =0;
            for(int k=0;k<N;k++)
            {
                sum += b[i][k]*matrix[k][j];
            }
            d[i][j] = sum%1000;
        }
    }
    for(int i =0 ; i<N; i++)
    {
        for(int k=0;k<N;k++)
        {
            c[i][k] = d[i][k];
        }
    }
}

void Mat_print()
{
    for(int i=0; i<N ; i++)
    {
        for(int j=0;j<N;j++)
        {
            printf("%d ",c[i][j]);
        }
        printf("\n");
    }
}

int main(void)
{
    long long int B;
    scanf("%d " , &N);
    scanf("%lld" , &B);getchar();
    MakeMat();
    if(B==1)
    {
        MatMul(matrix,c,c);
        B = B-1;
    }
    while(B>0)
    {
        if(B %2 ==1)
        {
            MatMul(c,b,c);
            B = B-1;
        }
        else
        {
            MatMul(b,b,b);
            B = B/2;
        }
    }
    Mat_print();
    return 0;
}