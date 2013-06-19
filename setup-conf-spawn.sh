#!/bin/bash

fds=`ulimit -n`
let spawnlimit='(fds-6)/2'
if [ ! -f "conf-spawn.orig" ] ; then
  cp -pf conf-spawn conf-spawn.orig
fi
echo $spawnlimit >conf-spawn
