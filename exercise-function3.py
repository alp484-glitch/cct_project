# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


def power(base, exponent=2):
    # Use a breakpoint in the code line below to debug your script.
   return base ** exponent

if __name__ == '__main__':
    base_exponent = map(int, (input("base and exponent:").split(" ")))
    print(power(*base_exponent))


