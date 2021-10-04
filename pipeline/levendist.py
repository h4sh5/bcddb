#!/usr/bin/env python3

#https://stackoverflow.com/questions/2460177/edit-distance-in-python/32558749#32558749
def levenshteinDistance(s1, s2):
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2+1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]


import sys
if len(sys.argv) < 3:
    print("%s <string1> <string2>" % sys.argv[0])
    exit(1)

print(levenshteinDistance(sys.argv[1], sys.argv[2]))
