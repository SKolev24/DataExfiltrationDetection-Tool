import math

def calculate_entropy(data):
    entropy = 0
    freq = {}

    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy