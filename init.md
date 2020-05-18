# The `init` program

The `init` program takes one command line argument, as follows:

    % <path1>/init <path2>/<init-fname>

This program creates two files: `<path2>/<init-fname>.bank` and
`<path2>/<init-fname>.atm` -- the point of the paths here being that
the program should not be creating files in a hard-coded directory,
but rather the user should be able to specify where they go.

For example if your project is in `~/gitsrc/atm`, and you run (from an
arbitrary directory):

    % ~/gitsrc/atm/init /tmp/foo

your `init` program should create the files `/tmp/foo.bank` and
`/tmp/foo.atm`.

## File contents

The contents of these files can be *whatever you
want*.  In fact, their contents are an important part of your
protocol's design and security. When you design them, keep in mind:

 * When the `bank` program is started, we pass it the
   `<init-fname>.bank` file, and when the `atm` program is started, we
   pass it the `<init-fname>.atm` file.

 * *Only* the bank can access the `.bank` file, and only the ATM can
   access the `.atm` file--they cannot access one another's.

 * Attackers are *not* allowed to access either of these files.

## Behavior of the `init` program

 * If the user fails to provide precisely one argument, then print
   
       Usage:  init <filename>
   
   and return value 62.

 * Otherwise, if either `<path2>/<init-fname>.atm` or
   `<path2>/<init-fname>.bank` already exist, print
   
       Error: one of the files already exists
   
   and return value 63 without writing over or creating *either* file.

 * Otherwise, if for any reason the program fails, print
   
       Error creating initialization files
   
   and return value 64 (you do not need to delete or revert any files
   you may have created).

 * Otherwise, if successful, print
   
       Successfully initialized bank state
   
   and return value 0.
