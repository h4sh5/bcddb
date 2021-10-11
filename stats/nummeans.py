#!/usr/bin/env python3
import statistics
# read numbers one line each, then calculate mean
nums = []

while True:
	try:
		n = float(input())
		nums.append(n)
	except EOFError:
		break

print(statistics.mean(nums))

