import subprocess

#  ./error_handler.sh -i logfile.log
result = subprocess.run(["bash", "error_handler.sh", "-i", "logfile.log"], capture_output=True, text=True)

print("Return code:", result.returncode)
print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
