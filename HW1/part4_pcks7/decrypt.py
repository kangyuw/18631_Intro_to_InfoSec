from pwn import *
import copy

context.log_level = 'error'

context.proxy = (socks.SOCKS5, 'localhost', 8123)

"""
I should get:

len = 192*4 = 6 blocks = IV + 5 blocks

Decryption Attack:

1. Altering sampleBlocks
2. Check Valid
3. semiCipher = validCipher ^ Padding
4. originalPlain = semiCipher ^ originalCipher

Pi = {"username": "guest", "expires": "xxxx-xx-xx", "is_admin": "false"} + Padding

for the last byte of last block, there might be 2 situation
1. padding = 0x01, only one valid padding
2. padding != 0x01, two valid padding (original and x01)
"""

def makeMessage(blocks):
    message = ""
    for block in blocks:
        for item in block:
            message += item
    return message

def getPadding(i):
    return str("{:02x}".format(16-i))

def xorString(str1, str2):
    res = b""
    for a,b in zip(bytes.fromhex(str1), bytes.fromhex(str2)):
        res += bytes([a^b])
    return res.hex()

sample = [ ## originalCipher
    "5468697320697320616e204956343536", ## "This is an IV456"
    "0ca408a2aaa734602e0153fcfdeb575a",
    "c8ee13cdf1c60b0958cbcbaa6bc05c73",
    "5f7c31bd2e3d068a5dfcb8cead861c65",
    "320446515d3195fd21983d7354666bfd", ## Start here
    "db84f4baf0a79081e1794bd58186cc0a"
]

originalCipher = []

## Spliting sample ciphertext
for block in sample:
    temp = [block[i:i+2] for i in range(0, len(block), 2)]
    originalCipher.append(temp)

validCipher = [["" for _ in range(16)] for _ in range(6)]
semiCipher = [["" for _ in range(16)] for _ in range(6)]
originalPlain = [["" for _ in range(16)] for _ in range(6)]

for b in range(3, 0, -1): ## start from S[4] to S[1]
# b = 0
    sendBlocks = copy.deepcopy(originalCipher[:b+2])
    for i in range(15,-1,-1): ## start from i[15] to i[0]
        padding = getPadding(i)
        ## making new sendBlocks
        for j in range(i+1,16):
            temp = xorString(semiCipher[b][j], padding)
            sendBlocks[b][j] = temp

        for v in range(256):
            x = str("{:02x}".format(v))
            print(f"Block: {b}, Byte {i}, Value {x}")
            
            sendBlocks[b][i] = x
            sendMessage = makeMessage(sendBlocks)
            
            oracle = remote('192.168.2.83', 32830)
            oracle.recvuntil('?\n')
            oracle.sendline(sendMessage)
            response = oracle.recvline()
            oracle.close()

            if b'invalid' not in response and x != originalCipher[b][i]:
                print(f"{x} is a Valid byte\n")
                validCipher[b][i] = x
                semiCipher[b][i] = xorString(validCipher[b][i], padding)
                originalPlain[b][i] = xorString(originalCipher[b][i], semiCipher[b][i])
                break
            ## only happen in the last block
            # x = originalCipher[b][i]
            # print(f"{x} is a Valid byte\n")
            # validCipher[b][i] = x
            # semiCipher[b][i] = xorString(validCipher[b][i], padding)
            # originalPlain[b][i] = xorString(originalCipher[b][i], semiCipher[b][i])


print(f"validCipher: \n{makeMessage(validCipher)}\n")
print(f"semiCipher: \n{makeMessage(semiCipher)}\n")
print(f"originalPlain: \n{makeMessage(originalPlain)}\n")
