#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>

#define CMD_INIT 1
#define CMD_BUY 2
#define CMD_SELL 3
#define CMD_CANCEL 4
#define CMD_BEST_PROFIT 5
#include <iostream>
#include <list>
#include <algorithm>

using namespace std;
extern void init();
extern int buy(int mNumber, int mStock, int mQuantity, int mPrice);
extern int sell(int mNumber, int mStock, int mQuantity, int mPrice);
extern void cancel(int mNumber);
extern int bestProfit(int mStock);

/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

static bool run()
{
    int numQuery;

    int mNumber, mStock, mQuantity, mPrice;

    int userAns, ans;

    bool isCorrect = false;

    scanf("%d", &numQuery);

    for (int i = 0; i < numQuery; ++i)
    {
        int cmd;
        scanf("%d", &cmd);
        switch (cmd)
        {
        case CMD_INIT:
            init();
            isCorrect = true;
            break;
        case CMD_BUY:
            scanf("%d %d %d %d", &mNumber, &mStock, &mQuantity, &mPrice);
            userAns = buy(mNumber, mStock, mQuantity, mPrice);
            scanf("%d", &ans);
            cout << "여기 추측값 뭐야?" << endl;
            cout << userAns << endl;
            cout << "여기 답 뭐야?" << endl;
            cout << ans << endl;
            if (userAns != ans)
            {
                isCorrect = false;
            }
            break;
        case CMD_SELL:
            scanf("%d %d %d %d", &mNumber, &mStock, &mQuantity, &mPrice);
            userAns = sell(mNumber, mStock, mQuantity, mPrice);
            scanf("%d", &ans);
            cout << "여기 추측값 뭐야?" << endl;
            cout << userAns << endl;
            cout << "여기 답 뭐야?" << endl;
            cout << ans << endl;            
            if (userAns != ans)
            {
                isCorrect = false;
            }
            break;
        case CMD_CANCEL:
            scanf("%d", &mNumber);
            cancel(mNumber);
            break;
        case CMD_BEST_PROFIT:
            scanf("%d", &mStock);
            userAns = bestProfit(mStock);
            scanf("%d", &ans);
            cout << "여기 추측값 뭐야?" << endl;
            cout << userAns << endl;
            cout << "여기 답 뭐야?" << endl;
            cout << ans << endl;
            if (userAns != ans)
            {
                isCorrect = false;
            }
            break;
        default:
            isCorrect = false;
            break;
        }
    }

    return isCorrect;
}
#include <iostream>
#include <list>
#include <algorithm>

using namespace std;
int main()
{
   // init();
    setbuf(stdout, NULL);
    //freopen("sample_input.txt", "r", stdin);

    int T, MARK;
    scanf("%d %d", &T, &MARK);
   // int cc = buy(1,1,5,105);
   // int aa = buy(2, 1, 5, 100);
   // int bb = sell(3,1,12,100);
   
   
   // int dd = bestProfit(1);
   // int x1 = sell(4,1,8,90);
   // int x2 = sell(5,1,1,110);
   // int x3 = buy(6,1,11,110);
   // cout << cc << endl;
   // cout << aa << endl;
   // cout << bb << endl;
   // cout << dd << endl;
   // cout << x1 << endl;
   // cout << x2 << endl;
   // cout << x3 << endl;

    for (int tc = 1; tc <= T; tc++)
    {
        int score = run() ? MARK : 0;
        printf("#%d %d\n", tc, score);
    }
   // run();
    return 0;
}
#include <iostream>
#include <list>
#include <algorithm>

using namespace std;




typedef struct stock {
   int number;
   int stocknum;
   int quantity;
   int price;
}stock;
bool compareA(const stock& a1, const stock&a2) {
	return a1.price < a2.price ;
}
list <struct stock> a;  // a => Buy
list <struct stock> b;  // b => Sell
list <struct stock> c;
list <struct stock> d;

void init()
{

   while (a.size() != 0) {
      a.pop_back();
   }
   while (b.size() != 0) {
      b.pop_back();
   }
   while (c.size() != 0) {
      c.pop_back();
   }
   while (d.size() != 0) {
      d.pop_back();
   }
}



int buy(int mNumber, int mStock, int mQuantity, int mPrice)
{
   // cout << mNumber << endl;
   // cout << mQuantity << endl;
   struct stock buystock;   
   buystock.number = mNumber;
   buystock.stocknum = mStock;
   buystock.quantity = mQuantity;
   buystock.price = mPrice;
   int d;
   struct stock e;
   list <struct stock>::iterator iter;
   if(b.empty()){
   a.push_back(buystock);
   }
   else
   {
    stock d1 = *std::min_element(b.begin(), b.end(), compareA) ;
    d = min(d1.price,mPrice);

    for(iter=b.begin();iter!=b.end();iter++)
    {
      //   cout<< (*iter).price << endl;
      //   cout<< (*iter).quantity << endl;
      //   cout<< buystock.quantity << endl;
      //   cout << "Hello는" << endl;

        if(b.size() ==0)
        {
          break;
        }
      //  cout << "Hello" << endl;
      //  cout << b.size() << endl;
        e = *iter;
        if(e.price == d && d<=mPrice)
        {
            if(e.quantity>buystock.quantity)
            {
                    if(buystock.quantity <=0)
                    {
                       break;
                    }
                    (*iter).quantity = (*iter).quantity - buystock.quantity;
                    buystock.quantity =0;
                    c.push_back(e);

            }
            else if(e.quantity<buystock.quantity)
            {
                    buystock.quantity = buystock.quantity - e.quantity;

                    b.erase(iter);
                    c.push_back(e);
                  //   cout << buystock.quantity << endl;
                    if(buystock.quantity <=0)
                    {
                       break;
                    }
                    else{
                    return buy(buystock.number,buystock.stocknum,buystock.quantity,buystock.price);
                    }
            }
            else
            {
               buystock.quantity = buystock.quantity - e.quantity;     
               b.erase(iter);
               c.push_back(e);
            }
        }

      //   cout<< buystock.quantity << endl;
      //   cout<< buystock.quantity << endl;
      //   cout<< buystock.quantity << endl;
      }
      a.push_back(buystock);
   }
   return buystock.quantity;
}

int sell(int mNumber, int mStock, int mQuantity, int mPrice)
{
   struct stock sellstock;
   sellstock.number = mNumber;
   sellstock.stocknum = mStock;
   sellstock.quantity = mQuantity;
   sellstock.price = mPrice;
   list <struct stock>::iterator iter;
   int d;
   struct stock e;
   if(a.empty())
   {
   b.push_back(sellstock);
   }
   else
   {

    stock d1 = *std::max_element(a.begin(), a.end(), compareA) ;
    d = max(d1.price,mPrice);
    for(iter=a.begin();iter!=a.end();iter++)
      {
       if(a.size() ==0)
       {
          break;
       }
       e = *iter;
       if(e.price == d && d>=mPrice)
       {
           if(e.quantity>sellstock.quantity)
           {
                 (*iter).quantity = (*iter).quantity - sellstock.quantity;
                 sellstock.quantity =0;
                 c.push_back(e);
           }
           else if(e.quantity<sellstock.quantity)
           {
                 sellstock.quantity = sellstock.quantity - e.quantity;
                 a.erase(iter);
                 c.push_back(e);
                //  cout<< "여기먼저" << endl;
                 return sell(sellstock.number,sellstock.stocknum,sellstock.quantity,sellstock.price);
                 
           }
           else
           {
                sellstock.quantity = sellstock.quantity - e.quantity;
                a.erase(iter);
                c.push_back(e);
           }
       }

      }
      b.push_back(sellstock);
   }
   // cout << b.size() << endl;
   // cout << b.size() << endl;
   // cout << b.size() << endl;

   return sellstock.quantity;
}

void cancel(int mNumber)
{
struct stock s;
   int finish = 0;

   list <struct stock>::iterator iter = a.begin();

   for (iter = a.begin(); iter != a.end();iter++) {
      s = *iter;
      if (s.number == mNumber) {
         a.erase(iter);
         finish = 1;
         break;
      }
   }
   if (finish != 1) {
      for (iter = b.begin(); iter != b.end(); iter++) {
         s = *iter;
         if (s.number == mNumber) {
            b.erase(iter);
            break;
         }
      }
   }
}

int bestProfit(int mStock)
{
    list <struct stock>::iterator iter_0;
    list <struct stock>::iterator iter_1;
    list <struct stock>::iterator iter_2;
    int x;
    int max_value = 0;
    for(iter_0=c.begin();iter_0!=c.end();iter_0++)
    {
        if((*iter_0).stocknum == mStock)
        {   if((*iter_0).price ==0)
            {
             continue;
            }
            else
            {
             d.push_back(*iter_0);
            }
        }    
    }
   for(iter_1=d.end();iter_1!=d.begin();iter_1--)
      {  
         if((*iter_1).price ==0)
         {
            continue;
         }
         for(iter_2=d.end();iter_2!=d.begin();iter_2--)
         {
            if((*iter_2).price ==0)
            {
               continue;
            }
            x = (*iter_1).price - (*iter_2).price;
            max_value = max(x,max_value);
         }
      }
    return max_value;
    }