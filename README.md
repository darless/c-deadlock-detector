# c-deadlock-detector
Python based deadlock detector for C programs

This python script can be used to detect if a program is in a deadlocked state and further more
gain more insight about potential threads that could be the culprits to the nasty deadlock.

Now I know that figuring out where a deadlock occurs is a lot fun and I don't want to take the
fun out of it trust me. So for the people that are new to C and have not had the joy of trying
to figure out what threads are causing a deadlock using GDB please just go and do it manually,
you'll learn a lot and it will help you greatly in your career.

Now for those that have done this once or twice you probably know that its a joyous time to
troubleshoot a deadlock and use various gdb commands like 'info threads', 'info reg', etc.
to figure out what threads are waiting for what locks and which threads are the owners of those
locks. In the case that you want an automated script that does those commands for you then this
is the script for you. Plus its python so no need to recompile if it needs a minor change, just
change and go.

# What do you need to run this program
1. Python
2. GDB
3. A program that is in a deadlock

# Lets troubleshoot a deadlock

## By Process ID
    # Grab the process id
    ps aux | grep <PROCESS>

    # Type the into the program
    ./deadlock_detector.py /path/to/program/binary <PID>

## By Core File
In some environments running batch commands on gdb do not work and the script
by process id will fail. In those cases you will want to save the core file
first from GDB.
    # Go into gdb and generate a core file
    gdb /path/to/program/binary PID
    (gdb) generate-core-file my-core

    # Run the script with the core file
    ./deadlock_detector.py /path/to/program/binary my-core
