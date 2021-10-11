#!/usr/bin/env python3

class BasicBlock:

	# each basic block has its name, and line number
	def __init__(self, name: str, startLine:int, code:str):
		# as in lines inside source code
		self.startLine = startLine
		self.endLine = endLine
		self.lines = endLine - startLine
		
		self.code = code
		self.name = name

class Function:

	def __init__(self, name: str, startLine:int):
		# as in lines inside source code
		self.startLine = startLine
		self.endLine = endLine
		self.lines = endLine - startLine

		self.name = name

		self.basicBlocks = []

	def addBasicBlock(self, bName, bStartLine, bCode):
		self.basicBlocks.append(BasicBlock(bName, bStartLine, bCode))


