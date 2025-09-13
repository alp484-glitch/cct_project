# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def if_palindrome(test):
    # Use a breakpoint in the code line below to debug your script.
    return test == test[::-1]

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    test = input("palindrome:")
    print(if_palindrome(test))


