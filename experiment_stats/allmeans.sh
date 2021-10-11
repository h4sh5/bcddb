for i in 32 64 128 256 512
do
	echo $i:
	grep mean allfuncs_$i.txt | cut -d ':' -f 2 | ./nummeans.py
	echo 
done
