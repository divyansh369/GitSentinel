import math
from collections import Counter

def calculate_entropy(text:str ) -> float:
    if not text:
        return 0
    
    entropy = 0
    frequency = Counter(text)

    for freq in frequency.values():
        probability = freq / len(text)
        entropy -= probability * math.log2(probability)
    return entropy

def is_high_entropy(string:str,threshold:float = 4.0) -> bool:
    return calculate_entropy(string) > threshold    