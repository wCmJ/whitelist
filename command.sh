#grep
grep -qn "word" file
grep -En '^word' file | grep -Eo '^[^:]+'
grep . file
grep -qxn "word" file
grep -nwF "word" file | grep -Eo '^[^:]+'
grep -qEn '^word' file
grep -qwF "word" file

#The "re" in "grep" stands for regular expressions.

#--help: print a help message briefly summarizing command-line options, and exit
#-V, --version: print the version number of gerp, and exit
#--color: will highlight keyword
#-n: prefix each matching line with the line number
#-i: perform a case-insensitive match
#-r: search to subdirectories
#-w: will ignore letters, digits, and underscores, but keep ~, !, @, #, $, %, ^, &, *, (, ), -, +
#-v: select non-matching lines
#fgrep is the same as running grep -F. In this mode, grep evaluates your PATTERN string as a "fixed string".


#sed
sed '3!d' file
sed 's/"//g' file
sed 's/\\n/$/g' file
sed -n '/wrod1/,/word2/p' file
sed '1,2d' file
sed 'word' file
sed '$word' file
sed -e "s/$word//g" file



#awk
awk '{print $4}' file
awk '{if($word>1) print $2}' file
awk 'BEGIN{FS="$"}{for(i=1;i<NF;i++){print $1}}' file
awk 'BEGIN{FS="\""}{print $2}' file









