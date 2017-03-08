#/bin/bash
#start si
SCRIPTLOK="/tmp/"$0".LOCK"
if ! mkdir ${SCRIPTLOK} 2>/dev/null; then
    echo "Myscript is already running." >&2
    exit 1
fi

trap "rm -rf ${SCRIPTLOK}; exit" INT TERM EXIT
#end si




while :; do
    #Your own function
done
