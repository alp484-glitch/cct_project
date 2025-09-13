# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def is_even(number):
    # Use a breakpoint in the code line below to debug your script.
   return number%2==0

def print_even_odd(number):
    # Use a breakpoint in the code line below to debug your script.
   print("Even" if is_even(number) else "Odd")

if __name__ == '__main__':
    number = int(input("number:"))
    print_even_odd(number)
