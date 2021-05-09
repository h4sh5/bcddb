# extract labels from retdec decompiler .ll output
# each label is a basic block (BB)

if (( $# != 1 )); then
    echo "Usage: $0 <file>"
    exit 1
fi

grep .*label.*\:.* $1  | grep -v '^;' | cut -d ':' -f 1


