 在讲述filter，map和reduce之前，首先介绍一下匿名函数lambda。
     lambda的使用方法如下：lambda [arg1[,arg2,arg3,...,argn]] : expression
     例如：
    
[python] view plaincopy
>>> add = lambda x,y : x + y  
>>> add(1,2)  
3  

     接下来分别介绍filter，map和reduce。
1、filter(bool_func,seq)：此函数的功能相当于过滤器。调用一个布尔函数bool_func来迭代遍历每个seq中的元素；返回一个使bool_seq返回值为true的元素的序列。
     例如：
     
[python] view plaincopy
>>> filter(lambda x : x%2 == 0,[1,2,3,4,5])  
[2, 4]  

     filter内建函数的python实现：
    
[c-sharp] view plaincopy
>>> def filter(bool_func,seq):  
    filtered_seq = []  
    for eachItem in seq:  
        if bool_func(eachItem):  
            filtered_seq.append(eachItem)  
    return filtered_seq  

2、map(func,seq1[,seq2...])：将函数func作用于给定序列的每个元素，并用一个列表来提供返回值；如果func为None，func表现为身份函数，返回一个含有每个序列中元素集合的n个元组的列表。
    例如：
    
[c-sharp] view plaincopy
>>> map(lambda x : None,[1,2,3,4])  
[None, None, None, None]  
>>> map(lambda x : x * 2,[1,2,3,4])  
[2, 4, 6, 8]  
>>> map(lambda x : x * 2,[1,2,3,4,[5,6,7]])  
[2, 4, 6, 8, [5, 6, 7, 5, 6, 7]]  
>>> map(lambda x : None,[1,2,3,4])  
[None, None, None, None]  

     map内建函数的python实现：
     
[python] view plaincopy
>>> def map(func,seq):  
    mapped_seq = []  
    for eachItem in seq:  
        mapped_seq.append(func(eachItem))  
    return mapped_seq  

3、reduce(func,seq[,init])：func为二元函数，将func作用于seq序列的元素，每次携带一对（先前的结果以及下一个序列的元素），连续的将现有的结果和下一个值作用在获得的随后的结果上，最后减少我们的序列为一个单一的返回值：如果初始值init给定，第一个比较会是init和第一个序列元素而不是序列的头两个元素。
     例如：
    
[c-sharp] view plaincopy
>>> reduce(lambda x,y : x + y,[1,2,3,4])  
10  
>>> reduce(lambda x,y : x + y,[1,2,3,4],10)  
20  

     reduce的python实现：
    
[python] view plaincopy
>>> def reduce(bin_func,seq,initial=None):  
    lseq = list(seq)  
    if initial is None:  
        res = lseq.pop(0)  
    else:  
        res = initial  
    for eachItem in lseq:  
        res = bin_func(res,eachItem)  
    return res 
    


#!/usr/bin/python
# python built-in map()/reduce() exercises.

print map(lambda x: x.title(), ['adam', 'LISA', 'barT', 'Jay'])


def prod(list1):
    return reduce(lambda x, y: x * y, list1)


list1 = xrange(1, 6)
print prod(list1)
