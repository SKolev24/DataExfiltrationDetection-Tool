import math

def calculate_entropy(data):
    # Stores how many times each letter appears
    char_appears = {}
    # Stores the final entropy value
    entropy = 0

    # Loops through each character in the string
    for ch in data:
        freq = char_appears.get(ch, 0)+ 1

    # Loop goes through the frequency of each character
    for count in freq.values():
        # Calculates the probability of each character
        p = count / len(data)
        # Calculates the entropy of each character
        entropy -= p * math.log2(p)
    # Returns the final entropy value
    return entropy