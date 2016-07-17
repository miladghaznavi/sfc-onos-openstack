#!/bin/bash

HEADING=$'cookie\tduration\ttable\tn_packets\tn_bytes\tpriority\trules'
#|sed -e $'s/ cookie=//g' -e $'s/, duration=/\t/g' -e $'s/, table=/\t/g' -e $'s/, n_packets=/\t/g' -e $'s/, n_bytes=/\t/g' -e 's/\(priority=\)\([0-9]*\)[ ,]/\t\2\t/g'|(echo "$HEADING" && cat)| column -t -s $'\t'
printf "$(cat $input|grep 'cookie'|sed -e $'s/ cookie=//g' -e $'s/, duration=/\t/g' -e $'s/, table=/\t/g' -e $'s/, n_packets=/\t/g' -e $'s/, n_bytes=/\t/g' -e 's/\(priority=\)\([0-9]*\)[ ,]/\t\2\t/g'|(echo "$HEADING" && cat)| column -t -s $'\t')"
echo $'\n'
