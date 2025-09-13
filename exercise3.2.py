# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def biggest(*test):
    # Use a breakpoint in the code line below to debug your script.
    temp_list = list(map(int,test))
    sorted_list = sorted(temp_list, reverse=True)
    return sorted_list[0]

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    test = str(input("three numbers:")).split(" ")
    print(biggest(*test))


