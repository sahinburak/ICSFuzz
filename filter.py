import re


def isNumber(val):
    if re.match(r'^[0-9]+$', val):
        return True
    return False

retvals = []
bufs = []
m1s_all = set()
bufval = 0
retval = 0
hundreds = set()

fw = open("icsfuzz_results_all", "a")
prev_tag = ""
for line in open("icsfuzz_results", "r", encoding="iso-8859-1"):
    line = line.strip()
    tokens = line.split(" : ")
    if line.startswith("buf"):
        bufval = line.split()[1]
        assert bufval.isdigit()
        bufs.append(bufval)
        if bufval != retval:
            print("diff ", bufval, retval)
        # fw.write(f"{line}\n")
    elif line.startswith("RETVAL"):
        retval = line.split()[1]
        assert retval.isdigit()
        retvals.append(retval)
        continue
    else:
    # elif tokens[0] in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9"]:
        ms = set()
        # print(tokens[0])
        # input()
        last_token = None
        for token in tokens:
            token = token.strip()
            # if token.isdigit():
            if isNumber(token):
                n = int(token)
                if n < 100:
                    hundreds.add(n)
                ms.add(token)
                if token != last_token:
                    fw.write(f"{token}\n")
                last_token = token
        # line = tokens[0] + " : " + " : ".join(ms)
        # fw.write(f"{line}\n")

        # if ms - ms_all:
        #     print(ms)
        #     input()
        # ms_all |= ms

        # print(len(tokens), len(set(tokens)))
        # print(tokens)



    # else:
    # print(line)


print(f"Bufs: {len(bufs)} : {len(set(bufs))}")
print(f"Retvals : {len(retvals)} : {len(set(retvals))}")
print(f"diffs: {len(set(bufs) - set(retvals))} : {len(set(retvals) - set(bufs))}")
print(f"m1s: {len(m1s_all)} : {len(set(m1s_all))}")
print(hundreds)
