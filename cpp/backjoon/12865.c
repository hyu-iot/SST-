#include <stdio.h>

int DP[101][100001];


int max_value(int a, int b)
{
    if(a>b)
        return a;
    else
        return b;
}
int main()
{

    int N , K ;
    int W[101], V[101];
    
    scanf("%d ", &N);
    scanf("%d", &K);getchar();

    for(int i=1; i<=N;i++ )
    {
        scanf("%d ", &W[i]);
        scanf("%d", &V[i]);getchar();
        
    }

    for(int i=1 ; i<=N;i++)
        {
            for(int j=1;j<=K;j++)
            {
                if(j-W[i]>=0)
                {
                    DP[i][j] = max_value(DP[i-1][j],DP[i-1][j-W[i]] + V[i]);
                }
                else
                    DP[i][j] = DP[i-1][j];        
            }
        }
    printf("최적의 값은 : %d \n" ,DP[N][K]);

    return 0;
}