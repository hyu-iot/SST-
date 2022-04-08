#include <stdio.h>
#include <string.h>
#define _CRT_SECURE_NO_WARNINGS


struct Person{
    char name[10];
    char address[50];
    char phone[15];
};

struct Person p1[100];

int count=0;
void list()
{
    int i;

    if(count==0) printf("비어있습니다. \n");
    else
    {
        printf("이름 \t 주소 \t 전화번호 \n");
        for(i=0;i<count;i++)
        {
            if(p1[i].name)
            {
            printf("%s \t %s \t %s\n",p1[i].name,p1[i].address,p1[i].phone);
            }
        }
    }
}

void write()
{
    count++;
    printf("추가할 이름: ");
    scanf("%s", p1[count-1].name);
    printf("추가할 주소: ");
    scanf("%s", p1[count-1].address);
    printf("추가할 번호: ");
    scanf("%s", p1[count-1].phone);
}
void search()
{
    int j=0;
    char search_name[10];
    printf("검색할 이름은 무엇입니까? ");
    scanf("%s",search_name);getchar();
    for(j;j<count;j++)
    {
        if(strcmp(search_name,p1[j].name)==0)
        {
            printf("이름 \t 주소 \t 전화번호 \n");
            printf("%s \t %s \t %s\n",p1[j].name,p1[j].address,p1[j].phone);
        }
    }
}
void del()
{
    int k = 0;
    char search_name_1[10];
    printf("지우고 싶은 이름은 무엇입니까?");
    scanf("%s",search_name_1);getchar();
    for(k;k<count;k++)
    {
        if(strcmp(search_name_1,p1[k].name)==0)
        {
            if(k == count-1)
            {
                count--;
            }
            for(int x = k; x<count-1;x++)
                {
                    p1[x] = p1[x+1];
                    count--;
                }
        }
    }
    
}
void menu()
{
    char choice;

    printf(" ---------------------------- \n");
    printf("메뉴를 선택해주세요 :)\n");
    printf("1. 목록보기 2. 새 주소록 추가 3. 주소록 검색 4. 주소록 삭제\n");
    scanf("%c",&choice);getchar();
    // scanf를 하게되면 뒤에 \n이 생기게 되는데 이를 getchar를 통해 없애준다.

    switch(choice)
    {
        case '1': list(); break;
        case '2': write();getchar();break; //write는 scanf를 직접 하기때문에 \n을 없애주기 위해 getchar()를 함
        case '3': search();break;
        case '4': del();break;
    }
    // 여기에 csv 만들어서 저장!!

}
int main(){
    int line=0;
    char tmp;
    FILE *f;
    f = fopen("memo.txt","r");
    
    if(f!=NULL)
    {
        while((fscanf(f,"%c",&tmp)!=EOF)) //이 부분을 실행하면 txt에 저장된 모든 값들이 나가버려서 close하고 다시 선언해야함
            if(tmp=='\n') line++;
        fclose(f);
        f = fopen("memo.txt","r");
        for(int j=0;j<line;j++)
        {
            fscanf(f,"%s %s %s\n", p1[j].name, p1[j].address, p1[j].phone);
            count++;
        }
    }
    // csv,txt 불러와서 p1에 넣기!(for문!)
    char a;
    printf("주소록을 실행하겠습니다. \n");    
    while(1)
    {   
        menu();
        printf("1. 계속진행 2. 종료: ");
        scanf("%c",&a);getchar();
        f = fopen("memo.txt","w");
        for(int i=0;i<count;i++)
        {
            fprintf(f, "%s %s %s\n",p1[i].name,p1[i].address,p1[i].phone);
        }
        fclose(f);

        if(a=='2') break;
        
    }
}