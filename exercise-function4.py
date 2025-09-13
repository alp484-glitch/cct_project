# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def min_max(numbers):
    # Use a breakpoint in the code line below to debug your script.
   sorted_numbers = sorted(numbers)
   return [sorted_numbers[i] for i in [0,-1]]

if __name__ == '__main__':
    numbers = list(map(int, (input("numbers:").split(" "))))
    min_max = min_max(numbers)
    print(f"min: {min_max[0]} and max: {min_max[1]}")
