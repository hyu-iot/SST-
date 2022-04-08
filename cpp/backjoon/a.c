#include <stdio.h>

#define max 5

int matrix[max][max];
int matrix_main[max][max];
int matrix_main_1[max][max];

void MakeMat(int n)
{
    int size = n*n;
    for(int i =0;i<n;i++)
    {
        for(int j =0 ; j<n ; j++)
        {
            scanf("%d", &matrix[i][j]);
            matrix_main[i][j] =  matrix[i][j];
        }
        getchar();
    }
}

void MatMul(int N)
{
    for(int i=0; i<N;i++)
    {
        for(int j=0;j<N;j++)
        {   
            int sum =0;
            for(int k=0;k<N;k++)
            {
                sum += matrix_main[i][k]*matrix[k][j];
            }
            matrix_main_1[i][j] = sum;
        }
    }
}

void Mat_copy(int N)
{
    for(int i=0; i<N;i++)
    {
        for(int j=0;j<N;j++)
        {
            matrix_main[i][j] = matrix_main_1[i][j];
        }
    }
}

void Mat_print(int N)
{
    for(int i=0; i<N ; i++)
    {
        for(int j=0;j<N;j++)
        {
            printf("%d ", matrix_main_1[i][j]%1000);
        }
        printf("\n");
    }
}

int main(void)
{
    int N;
    long long int B;
    scanf("%d " , &N);
    scanf("%lld" , &B);getchar();
    MakeMat(N);
    for(int a=1;a<B;a++)
    {
    MatMul(N);
    Mat_copy(N);
    }
    Mat_print(N);
    return 0;
}