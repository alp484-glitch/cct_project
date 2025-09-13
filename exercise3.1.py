# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def even_or_odd(test):
    # Use a breakpoint in the code line below to debug your script.
    if test % 2 == 0: result = "even"
    else: result = "odd"
    return result

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    result = int(input("even_or_odd:"))
    print(even_or_odd(result))


