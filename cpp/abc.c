 #include <stdio.h>

struct member{

	char data1[10];

	char data2[50];

	char data3[30];

};

int main(void)

{

	struct member m[5];

	int i;

	FILE *f;

	f=fopen("memo.txt","r");



	// fscanf(f,"%s %s\n",m[0].data1, m[0].data2);

	// fscanf(f,"%s %s\n",m[1].data1, m[1].data2);

	// fscanf(f,"%s %s\n",m[2].data1, m[2].data2);

	// fscanf(f,"%s %s\n",m[3].data1, m[3].data2);
	int line=0;
	char tmp;
	while((fscanf(f,"%c",&tmp)!=EOF))
		if(tmp=='\n') line++;
	// printf("%d\n", line);
	// printf("%d\n", line);

	fscanf(f,"%s %s\n",m[0].data1, m[0].data2);

	fscanf(f,"%s %s\n",m[1].data1, m[1].data2);
	// for(int j=0;j<line;j++)
	// {
	// 	fscanf(f,"%s %s \n", m[j].data1, m[j].data2);
	// 	// printf("%s \t %s\n", m[j].data1, m[j].data2);        
	// }

	fclose(f);



	for(i=0;i<4;i++)

		printf("%s %s\n",m[i].data1, m[i].data2);

	return 0;

}

