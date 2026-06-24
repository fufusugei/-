from math import gcd

def egcd(a,b):
    if b==0:
        return a,1,0
    g,x,y=egcd(b,a%b)
    return g,y,x-a//b*y

def invmod(a,m):
    return egcd(a,m)[1]%m

def crack(n1,n2,e,c):
    p=gcd(n1,n2)
    q=n1//p
    phi=(p-1)*(q-1)
    d=invmod(e,phi)
    return pow(c,d,n1)

n1=int(input())
n2=int(input())
e=int(input())
c=int(input())

print(crack(n1,n2,e,c))