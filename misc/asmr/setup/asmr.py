import subprocess
import random
import os

# ASM template
asm_template = """
section .data:
    flag db "CCSC{{th@T_w@5_3asY_d0nt-G3t_c0Cky!!!}}", 0
section .text:
    global _start
_start :
    ; User-provided assembly code
    {user_code}
    mov eax, 1
    xor ebx, ebx
    int 0x80;
"""

# Prompt the user for their assembly code
print("******************************************************\n flag db \"FLAG{{1m_n0T_Th3_r34L_FL@6..0r_AM_I?}}\", 0\n******************************************************")
print("Enter your assembly code (press Enter for newline, twice to finish):")
user_code = []
while True:
    line = input()
    if line.strip() == "":
        break
    user_code.append(line)

user_code = "\n".join(user_code)

# Create the complete assembly code with user-provided code
asm_code = asm_template.format(user_code=user_code)

# Write asm to file
with open("asm_asmr.asm", "w") as f:
    f.write(asm_code)

# Compile the assembly
subprocess.run(["nasm", "-felf32", "-o", "asm_asmr.o", "asm_asmr.asm"], stderr=subprocess.DEVNULL)
subprocess.run(["ld", "-m", "elf_i386", "-o", "asm_asmr", "asm_asmr.o"], stderr=subprocess.DEVNULL)

# Run the asm_asmr
try:
	p = subprocess.Popen("./asm_asmr", stdout=subprocess.PIPE)


	# Read output
	output = p.stdout.read().decode()


	failure_messages = [
		"Oops! Looks like you failed again. Better luck next time!",
		"Failures are stepping stones to success. You're stepping quite well!",
		"Failed once, failed twice... it's becoming a trend!",
		"Failure is just success in progress. You must be making excellent progress!",
		"You've failed, but at least you've mastered the art of trying!",
		"Remember, failure is not falling down but refusing to get up. You're doing great!",
		"Failures are the spice of life. You must be having a very flavorful life!",
		"Failure is simply the opportunity to begin again, more intelligently. You're getting smarter!",
		"If at first, you don't succeed, congratulations! Most people stop there.",
		"The only true failure is the failure to try. And boy, you've definitely tried!"
	]


	# Check if the flag is present in the output

	if "CCSC{" in output:
		print("NO NO NO NO NO!!! WHAT ARE YOU DOING MATE?\n",output)
	else:
		random_message = random.choice(failure_messages)
		print(random_message)
	os.remove("asm_asmr")
	os.remove("asm_asmr.o")
	os.remove("asm_asmr.asm")
except:
	print("\nSomething broke, GOOD JOB GENIUS!\n")
