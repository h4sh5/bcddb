#!/bin/bash

# example data produced: (in a table)
# P=64	Combined ARM	Combined MIPS	combined i386
# KSA ARM	0.65625	0.53125	0.421875
# KSA MIPS	0.53125	0.734375	0.484375
# KSA i386	0.25	0.328125	0.796875
# PRGA ARM	0.625	0.5	0.390625
# PRGA MIPS	0.546875	0.78125	0.40625
# PRGA i386	0.46875	0.515625	0.578125

if (( $# != 1 )); then
	export P=64
else
	export P=$1
fi



# rg is ripgrep, apt install ripgrep

# each of these comparisons are comparing the combined RC4 function with the KSA and PRGA function for containment

ARM_KSAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg arm_combined |rg KSA |cut -d , -f 4 |tr -d  ' ')

MIPS_KSAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg mips_combined |rg KSA |cut -d , -f 4 |tr -d  ' ')

x86_KSAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg i386_combined | rg 1267 | rg KSA |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_KSAARM\t$MIPS_KSAARM\t$x86_KSAARM"

###

ARM_KSAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg arm_combined |rg KSA |cut -d , -f 4 |tr -d  ' ')

MIPS_KSAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg mips_combined |rg KSA |cut -d , -f 4|tr -d  ' ')

x86_KSAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg i386_combined | rg 1267 | rg KSA |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_KSAMIPS\t$MIPS_KSAMIPS\t$x86_KSAMIPS"

####

ARM_KSA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg arm_combined |rg 1267 |cut -d , -f 4|tr -d  ' ')

MIPS_KSA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg mips_combined |rg 1267 |cut -d , -f 4|tr -d  ' ')

x86_KSA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg i386_combined |rg "1267.*1267" |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_KSA86\t$MIPS_KSA86\t$x86_KSA86"

##############


ARM_PRGAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg arm_combined |rg PRGA |cut -d , -f 4 |tr -d  ' ')

MIPS_PRGAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg mips_combined |rg PRGA |cut -d , -f 4 |tr -d  ' ')

x86_PRGAARM=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg arm_RC|rg i386_combined | rg PRGA | rg 1267 |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_PRGAARM\t$MIPS_PRGAARM\t$x86_PRGAARM"

##


ARM_PRGAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg arm_combined |rg PRGA |cut -d , -f 4 |tr -d  ' ')

MIPS_PRGAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg mips_combined |rg PRGA |cut -d , -f 4 |tr -d  ' ')

x86_PRGAMIPS=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg mips_RC|rg i386_combined | rg PRGA | rg 1267 |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_PRGAMIPS\t$MIPS_PRGAMIPS\t$x86_PRGAMIPS"


##

ARM_PRGA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg arm_combined |rg 1330 |cut -d , -f 4 |tr -d  ' ')

MIPS_PRGA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg mips_combined |rg 1330 |cut -d , -f 4 |tr -d  ' ')

x86_PRGA86=$(./run_experiments.py -p$P  compare -a minhash -f @RC4,@KSA,@PRGA,@function_1267,@function_1330 -d customdata/ 2>/dev/null |rg -v llvm| rg i386_RC|rg i386_combined | rg 1330 | rg 1267 |cut -d , -f 4 |tr -d  ' ')

echo -e "$ARM_PRGA86\t$MIPS_PRGA86\t$x86_PRGA86"


