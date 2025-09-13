# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def count_vowels(test):
    # Use a breakpoint in the code line below to debug your script.
    vowels = ["a", "e", "i", "o", "u"]
    return sum(1 for char in test if char.lower() in vowels)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    test = input("words:")
    print(count_vowels(test))


