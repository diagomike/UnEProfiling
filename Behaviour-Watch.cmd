@echo off
rem Double-click to open the Behaviour Watch console in your browser. Drop a watch folder on this file to open that one.
rem With nothing dropped it opens the CERT test watch (build it first: python behaviour_watch.py demo).
rem Close this window to stop it. Add --lan --password WORD to let other computers on the network connect.
title Behaviour Watch
cd /d "%~dp0"
start "" http://127.0.0.1:8770
python behaviour_watch.py serve %*
pause
