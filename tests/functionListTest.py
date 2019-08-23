
def func(i):
    print("in func{}".format(i))


funcList = [func for i in range(5)]
#funcCallList = [func1(),func2(),func3()]


print("funcList")
for i,func in enumerate(funcList):
    func(i)