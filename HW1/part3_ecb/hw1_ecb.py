ca ="a42b7d2216a00b8af99c5e65a2dbff66b191f54a892be5225b0b8144d9751b9c507b6f896068ed5fbf1c8fdcf295ecb86af20fee3b2f009bceb0de6618c3cf6f"
cu = "e334eef97046b1b698f9b08d7cc30271b191f54a892be5225b0b8144d9751b9c507b6f896068ed5fbf1c8fdcf295ecb860e0652a5678a96a87dd8931b50f82ff"

pa = "I am yes an administrator. This cookie expires 2010-01-01......."

pu = "I am not an administrator. This cookie expires 2021-05-01......."

ct = ca[:len(ca)//2] + cu[len(cu)//2:]
print(ct)