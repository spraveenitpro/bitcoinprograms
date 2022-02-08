lower = int(input("Enter the lower interval value: "))
upper = int(input("Enter the upper interval value: "))

for num in range(lower, upper):
    for x in range(2, num):
        if num%x==0:
            break
    else:
        print(num)