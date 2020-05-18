# The `bank` program

The `bank` program takes one command line argument, as follows:

    % <path1>/bank <path2>/<init-fname>.bank

That is, it is called with a `<init-fname>.bank` that was created by
the `init` program. You can assume that it will NOT be called with any
other file than one that was created with your `init` program.

## Behavior of the `bank` program

 * If `<init-fname>.bank` cannot be opened, print
   
       Error opening bank initialization file
   
   and return value 64.

 * Otherwise, present the bank prompt
   
       BANK: 
   
   (note the space at the end) and process bank commands, as described
   below.

### Bank commands
The bank should support the following commands:

 * `create-user <user-name> <pin> <balance>`
    * Inputs
       * `<user-name>`: a name that can consist only of upper and lower
         case characters (`[a-zA-Z]+`). (Valid user names are at most 250
         characters.)
       * `<pin>`: a four-digit number `[0-9][0-9][0-9][0-9]`
       * `<balance>`: a non-negative integer `[0-9]+` at most what can be
         be represented with an `int`.
    * Behavior
       * If the inputs to the command are invalid, then print
         
             Usage:  create-user <user-name> <pin> <balance>
         
         There should be no side effects in this case.
       * Otherwise, if there is already a user with that (case-sensitive)
         name, then print
         
             Error:  user <user-name> already exists
         
         There should be no side effects in this case.
       * Otherwise, it should create a user named `<user-name>` in
         the bank with an initial balance of `$<balance>`. It should
         also create a file called `<user-name>.card` in the current
         directory. (If you run `./<path>/bank` then it should create
         the file in `.`, not in `<path>`.) Like with the `<init-fname>`
         files, the contents can be whatever you want: it's part of your
         design.
          * If it is unable to create the file, then it should print
            
                Error creating card file for user <user-name>
            
            and roll back any changes the bank may have made.
          * Otherwise, if it successfully creates the file, then it should
            print

                Created user <user-name>

       * In any of the above cases, it should return the user back to
         the bank prompt for more commands.
       * **Note:** Your protocol cannot modify card files after creating them.
       * **Note:** The bank should not have any user accounts pre-established:
         these will be created at run-time with a `create-user` command.
 * `deposit <user-name> <amt>`
    * Inputs
       * `<user-name>`: a name that can consist only of upper and lower
         case characters (`[a-zA-Z]+`). (Valid user names are at most 250
         characters.)
       * `<amt>`: a non-negative integer `[0-9]+` at most what can be
         be represented with an `int`.
    * Behavior
       * If the inputs to the command are invalid, then print

             Usage:  deposit <user-name> <amt>

         There should be no side effects in this case.
       * Otherwise, if there is no such user, then print

             No such user

         There should be no side effect in this case.
       * Otherwise, if the `<amt>` would cause integer overflow, then
         print

             Too rich for this program

         There should be no side effect in this case.
       * Otherwise, the command will add `$<amt>` to the account of
         `<user-name>`. After successful completion of this command,
         this should print

             $<amt> added to <user-name>'s account

 * `balance <user-name>`
    * Inputs
       * `<user-name>`: a name that can consist only of upper and lower
         case characters (`[a-zA-Z]+`). (Valid user names are at most 250
         characters.)
    * Behavior
       * If the inputs to the command are invalid, then print

             Usage:  balance <user-name>

       * Otherwise, if there is no such user, then print

             No such user

       * Otherwise, if `<user-name>`'s current balance is `<balance>`, then
         the command with print

             $<balance>

       * No matter the input, this command should have no side effects
         (beyond printing).
 * Any other commands are invalid (note that withdrawals are not supported
   at the bank), and should result in printing

       Invalid command

## Example transcript

Here is an example transcript of using the bank: suppose that no users
exist yet.

    BANK: balance Alice
    No such user
    
    BANK: create-user Alice 1234 100
    Created user Alice
    
    BANK: deposit Alice 2
    $2 added to Alice's account
    
    BANK: balance Alice
    $102
    
    BANK: 
