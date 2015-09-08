#!/usr/bin/python

"""C deadlock detector

Designed to look at a program through GDB and see whether there is a
deadlock as well as to pin point the threads that are likely causing
the deadlock.
"""

from __future__ import print_function
import os, sys, argparse, re
import subprocess, shlex

__author__ = "Nodar Nutsubidze"
__licence__ = "GPL"

if os.system("which gdb") != 0:
  print("Could not find 'gdb' on the system. Exiting")
  sys.exit(1)

class GDB:
  def __init__(self, binary, pid):
    """Initialize the GDB object"""
    self.binary = binary
    self.pid = pid
    self.threads = []
    self.num_locked = 0
    self.deadlock_threads = []

  @property
  def base(self):
    """Return the base gdb command to run"""
    return "gdb {} {}".format(self.binary, self.pid)

  def get_output(self, cmd):
    """Perform a gdb batch command

    Args:
      cmd (str or list): Command(s) to perform

    Returns(str):
      GDB output of the commands that were performed
    """
    cmds = []
    if type(cmd) is list:
      cmds = cmd
    else:
      cmds = [cmd]
    full = "{} --batch".format(self.base)
    for item in cmds:
      full += " -ex '{}'".format(item)
    dev_null = open(os.devnull, 'w')
    result = subprocess.check_output(shlex.split(full), stderr=dev_null)
    dev_null.close()
    return result

  def parse_thread_state(self):
    """Parse the state of the threads"""
    lines = self.get_output('thread apply all bt').split('\n')
    thread = None
    for line in lines:
      if thread:
        if not line:
          # End of the thread
          thread = None
          continue
        if line[0] != '#':
          print("Skipping invalid frame: {}".format(line))
          continue
        thread.add_frame(line)
      elif line.find('Thread ') == 0:
        # New thread
        match = re.match('Thread ([0-9]*) \(Thread (0x[a-f0-9]*) \(LWP ([0-9]*)\)\)', line)
        if not match:
          print("No match for thread {}".format(line))
          continue
        data = match.groups()
        thread = Thread(self, data[0], data[1], data[2])
        self.threads.append(thread)
    for line in self.get_output('info threads').split('\n'):
      match = re.search('\(LWP ([0-9]*)\) "([a-zA-Z0-9_-]*)"', line)
      if match:
        self.set_thread_name(match.group(1), match.group(2))
    self.set_locks()
    self.find_deadlock()

  def set_thread_name(self, lwp, name):
    """Set a thread name based on the LWP that is passed in

    Args:
      lwp (str): The LWP as seen in GDB for a given thread
      name (str): The name of the thread
    """

    th = self.thread_by_lwp(lwp)
    if th:
      th.name = name
    else:
      print("No thread found with lwp: {}".format(lwp))
      print("Threads: {}".format([th.lwp for th in self.threads]))

  def set_locks(self):
    """What functions were called before the lock"""
    for th in self.threads:
      if th.locked:
        th.lock_func = None
        for frame in th.frames:
          if frame.index > th.locked_index:
            if frame.at_file and frame.in_func:
              th.lock_func = frame.in_func
              break

  def find_deadlock(self):
    """Figure out if there really is a deadlock"""
    for th in self.threads:
      if th.locked:
        owner = self.thread_by_lwp(th.lock_owner_lwp)
        if (owner and
            owner.locked and
            owner.lock_owner_lwp and
            owner.lock_owner_lwp == th.lwp):
          self.deadlock_threads.append((th, owner))

  def print_status(self, show_bt=False, only_show=None):
    """Print the status of the threads

    Args:
      show_bt (bool): Whether to show the back trace for the locked threads
    """
    if not self.num_locked:
      print("There are no locked threads")
      return
    threads = []
    # Filter threads
    for th in self.threads:
      if not th.locked:
        continue
      if not only_show:
        threads.append(th)
      if th.index in [int(x, 10) for x in only_show]:
        threads.append(th)
      if th.name and th.name in only_show:
        threads.append(th)

    for th in threads:
      owner = self.thread_by_lwp(th.lock_owner_lwp)
      if not owner:
        print("No owner for {}".format(th.readable()))
        continue

      # We want to print the back track
      if show_bt:
        print("=" * 80)
      print("{} is waiting for a lock ({}) owned by {}"
        .format(th.readable(), th.lock_func, owner.readable()))
      if show_bt:
        th.print_backtrace()
        owner.print_backtrace()
    # Print out if there are any deadlocks
    for dl in self.deadlock_threads:
      print("Deadlock between {} and {}".format(
        dl[0].readable(), dl[1].readable()))


  def thread_by_lwp(self, lwp):
    """Retrieve a thread object by LWP id

    Args:
      lwp (str): The LWP id

    Returns(Thread)
    """
    for th in self.threads:
      if th.lwp == lwp:
        return th
    print("Did not find {} in {}".format(lwp, [th.lwp for th in self.threads]))
    return None

class Thread:
  def __init__(self, gdb, index, addr, lwp):
    """Initialize a new thread object

    Args:
      gdb (GDB): The GDB class object
      index (str): The thread index
      addr (str): Memory address of the thread
      lwp (str): The light weigh process id
    """
    self.gdb = gdb
    self.name = None
    self.index = int(index, 10)
    self.addr = addr
    self.lwp = lwp
    self.frames = []
    self.locked = False
    self.locked_index = None
    self.lock_func = None
    self.lock_owner_lwp = None

  def __str__(self):
    return ("{} {} {} Locked: {}".format(
      self.index, self.addr, self.lwp, self.locked))

  def readable(self):
    """Returns a readable version of the thread name"""
    data = "Thread #{}".format(self.index)
    if self.name:
      data += " {}".format(self.name)
    return data

  def print_backtrace(self):
    """Show the back trace of a thread"""
    print('\n{} {} {}'.format('-' * 20, self.readable(), '-' * 20))
    for frame in self.frames:
      print(frame.raw)

  def add_frame(self, line):
    """Add a frame to a thread

    Args:
      line (str): Frame line
    """
    frame = Frame(self, line)
    if frame.index == -1:
      print("Skipping invalid frame: {}".format(line))
    if frame.locked:
      self.locked = True
      self.locked_index = frame.index
      self.gdb.num_locked += 1
    self.frames.append(frame)

class Frame:
  def __init__(self, thread, data):
    """Initialize a frame object

    Args:
      thread (Thread): The thread object for the frame
      data (str): The data line to parse
    """
    self.thread = thread
    self.gdb = self.thread.gdb
    self.raw = data
    self.index = -1
    self.addr = None
    self.in_func = None
    self.args = None
    self.from_file = None
    self.at_file = None
    self.locked = False
    self.lock_type = None
    self.parse()

  def __str__(self):
    return ("#{} {} in: {} from: {} at: {} Locked: {}".format(
      self.index,
      self.addr,
      self.in_func,
      self.from_file,
      self.at_file,
      self.locked))

  def parse(self):
    """Parse a frame line from a gdb thread"""
    base_pattern = '#([0-9]*) *([a-zA-Z0-9_-]*).*'
    in_pattern = 'in ([\?a-zA-Z0-9_-]*) \(.*\)'
    file_pattern = '([,/.:_\-a-zA-Z0-9]*)'
    at_pattern = 'at ' + file_pattern
    from_pattern = 'from ' + file_pattern

    pattern = base_pattern
    found = []
    if self.raw.find(' in ') >= 0:
      found.append('in')
      pattern += ' ' + in_pattern
    if self.raw.find(' from ') >= 0:
      found.append('from')
      pattern += ' ' + from_pattern
    if self.raw.find(' at ') >= 0:
      found.append('at')
      pattern += ' ' + at_pattern
    match = re.match(pattern, self.raw)
    if not match:
      print("{} did not match the pattern: {}".format(self.raw, pattern))
      return
    data = match.groups()
    self.index = int(data[0], 10)
    self.addr = data[1]
    if 'in' in found:
      self.in_func = data[2]
      if 'from' in found:
        self.from_file = data[3]
      elif 'at' in found:
        self.at_file = data[3]
    elif 'at':
      self.at_file = data[2]
    if self.in_func:
      if 'pthread_mutex_lock' in self.in_func:
        self.locked = True
        self.lock_type = 'pthread_mutex_t'
      elif 'pthread_rwlock' in self.in_func:
        self.locked = True
        self.lock_type = 'pthread_rwlock_t'
      if self.locked:
        self.parse_locked_state()

  def parse_locked_state(self):
    """Fiture out what thread is causing this thread to wait"""
    sep = '======='
    lines = self.gdb.get_output([
      "thread {}".format(self.thread.index),
      "frame {}".format(self.index),
      "echo {}\n".format(sep),
      "info reg",
    ]).split('\n')
    found_sep = False
    found_special = False
    for line in lines:
      if not found_sep:
        if line.find(sep) == 0:
          found_sep = True
        continue
      else:
        arr = line.split()
        if len(arr) != 3:
          continue
        register, mem_addr, val = arr
        # Need to have some way to know what memory address to look
        # at. I know this is silly but at the moment the only pattern I've
        # found is that the memory address to look at is after mem_addr is
        # 0x80 and value is 128
        if mem_addr == '0x80' and val == '128':
          found_special = True
          continue
        if found_special:
          if self.lock_type == 'pthread_mutex_t':
            info = self.gdb.get_output("p *(pthread_mutex_t*){}".format(mem_addr))
            match = re.search('__owner = ([0-9]*)', info)
            if match:
              self.thread.lock_owner_lwp = match.groups()[0]
            else:
              print("No match found for thread #{} frame #{}".format(
                self.thread.index, self.index))
          else:
            print("Unable to handle type {} atm".format(self.lock_type))
          break

if __name__ == "__main__":
  def ap_detector(args):
    gdb = GDB(args.binary, args.pid)
    gdb.parse_thread_state()
    gdb.print_status(show_bt=args.back_trace, only_show=args.thread)

  def add_sp(sub_p, action, func=None, help=None):
    p = sub_p.add_parser(action, help=help)
    if func:
      p.set_defaults(func=func)
    return p

  parser = argparse.ArgumentParser(description = 'C deadlock detector')
  parser.add_argument('binary', help='Path to the binary')
  parser.add_argument('pid', help='PID or Core File of the process')
  parser.add_argument('-b', '--back-trace', action='store_true',
                      help='Show the back trace for locked threads')
  parser.add_argument('-t', '--thread', action='append',
                      default=[],
                      help='Only show the threads provided that are locked')
  args = parser.parse_args()
  ap_detector(args)
