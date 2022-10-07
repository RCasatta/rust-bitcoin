#!/bin/bash

# Continuosly cycle over fuzz targets running each for 1 hour.
# It uses high niceness so that other process takes priority.
# For batch processes niceness works ok, but if you need 
# interactivity on the server it's not great.
# In the latter case considering limiting CPU cores dedicated to 
# fuzzing or change schedules with `chrt`.
#
# For hfuzz options see https://github.com/google/honggfuzz/blob/master/docs/USAGE.md

export HFUZZ_BUILD_ARGS='--features honggfuzz_fuzz'

while :
do
  for FILE in fuzz_targets/*; 
  do 
    TARGET=$(echo $FILE | cut -c 14- | cut -f 1 -d '.')

    # fuzz for one hour
    HFUZZ_RUN_ARGS='--run_time 3600' nice -n 10 cargo hfuzz run $TARGET

    # minimize the corpus
    HFUZZ_RUN_ARGS="-i hfuzz_workspace/$TARGET/input/ -P -M" cargo hfuzz run $TARGET
  done
done

