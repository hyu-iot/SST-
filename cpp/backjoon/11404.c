#include <stdio.h>
#define Max_n 110
#define INF 10000000

int matrix[Max_n][Max_n];

void init_mat(int n)
{
    for(int i =1 ; i<=n ; i++)
    {
        for (int j=1 ; j<=n; j++)
        {
            matrix[i][j] = INF;
            if(i==j)
                matrix[i][j] =0;
        }
    }
}

int Min(int a, int b)
{
    if(a>b)
        return b;
    else    
        return a;
}

void floyd(int n)
{
    for(int k=1; k<=n ; k++)
    {
        for(int i=1; i<=n; i++)
        {
            for(int j=1; j<=n;j++)
            {
                matrix[i][j] = Min(matrix[i][j],matrix[i][k]+matrix[k][j]); 
            }
        }

    }
}

int main(void)
{
    int n, m;

    scanf("%d", &n);
    scanf("%d", &m);getchar();
    init_mat(n);
    int x,y,z;
    for(int i = 0; i<m ; i++)
    {
        scanf("%d ", &x);
        scanf("%d ", &y);
        scanf("%d", &z);
        if(matrix[x][y] >z)
            matrix[x][y] = z;

    }
    floyd(n);

    for (int i = 1; i <= n; i++)
        for (int j = 1; j <= n; j++)
            if (matrix[i][j] == INF)
                matrix[i][j] = 0;
    
    
    for(int i =1; i<=n; i++)
    {
        for(int j=1 ;j<=n;j++)
        {
            printf("%d ", matrix[i][j]);
        }
        printf("\n");
    }
    return 0;
}
