import sys
import re
from keystone import Ks, KS_ARCH_ARM64

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <input.c> [output.c]")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2] if len(sys.argv) > 2 else "output.c"

# ARM64 Keystone instance
ks = Ks(KS_ARCH_ARM64, 0)

pattern = re.compile(r'ADD\("(.+?)"\);')

output_lines = []

with open(input_file) as f:
    for line in f:
        def repl(match):
            asm_code = match.group(1)
            try:
                encoding, _ = ks.asm(asm_code)
            except Exception as e:
                print(f"Error assembling '{asm_code}': {e}")
                sys.exit(1)

            if len(encoding) % 4 != 0:
                print(f"Error: '{asm_code}' produced non-4-byte encoding: {encoding}")
                sys.exit(1)

            words = []
            for i in range(0, len(encoding), 4):
                word = (
                    encoding[i]
                    | (encoding[i+1] << 8)
                    | (encoding[i+2] << 16)
                    | (encoding[i+3] << 24)
                )
                words.append(f"ibuf[o++] = 0x{word:08x};")
            return " ".join(words)

        newline = pattern.sub(repl, line)
        output_lines.append(newline)

with open(output_file, "w") as f:
    f.writelines(output_lines)

print(f"✅ ARM64 inline replacement complete → {output_file}")

