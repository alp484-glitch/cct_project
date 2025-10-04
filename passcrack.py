import hashlib

def crackPass(inputPass):
    try:
        passFile = open("passlist", "r")
    except:
        print("[-] Passlist file not found")

    for password in passFile:
        encPass = password.encode("utf-8")
        digest = hashlib.md5(encPass.strip()).hexdigest()
        if digest == inputPass:
            print(f"{password} Password found")

if __name__ == "__main__":
    crackPass("<PASSWORD>")
