# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def leap_year(test):
    # Use a breakpoint in the code line below to debug your script.
    return test % 4 == 0 and test % 100 != 0 or test % 400 == 0

if __name__ == '__main__':
    test = int(input("leap_year:"))
    print(leap_year(test))


