# The `atm` program

The `atm` program takes one command line argument, as follows:

    % <path1>/atm <path2>/<init-fname>.atm

That is, it is called with a `<init-fname>.atm` that was created by
the `init` program. You can assume that it will NOT be called with
any other file than one that was created with your `init` program.

## Behavior of the `atm` program

 * Similar to the bank, if `<init-fname>.atm` cannot be opened, print

       Error opening ATM initialization file

   and return value 64.
 * Otherwise, present the prompt

       ATM: 

   and process ATM commands, as described below. Again, note the space after
   the prompt.

### ATM commands
The ATM should support the following commands:

 * `begin-session <user-name>`

    This command is supposed to represent `<user-name>` walking up to
    the ATM and inserting their ATM card. It should then read from
    `<user-name>.card`, and prompt for a PIN. If the correct PIN is
    entered, print

        Authorized

    and then allow the user to execute the other three ATM commands
    (`balance`, `withdraw`, and `end-session`). Otherwise, print

        Not authorized

    and continue listening for further `begin-session` commands. More
    details:
     * Inputs
        * `<user-name>`: a name that can consist only of upper and lower
          case characters (`[a-zA-Z]+`). (Valid user names are at most 250
          characters.)
     * Behavior
        * If there is a user already logged in, the print

              A user is already logged in

        * Otherwise, if the inputs to the command are invalid, then print

              Usage: begin-session <user-name>

          There should be no side effects in this case.
        * Otherwise, if there is no such user registered with the bank,
          then print

              No such user

        * Otherwise, if your protocol uses the card files, then it should
          look for `<user-name>.card` in the current directory (e.g., if
          you run `<path>/atm` then it should look for `<user-name>.card`
          in `.`, not in `<path>`). If it is unable to open the file, then
          it should print

              Unable to access <user-name>'s card

        * Otherwise (if there is no error accessing the card file), then
          the program should prompt the user for their PIN by printing

              PIN? 

          Again, note the space after the prompt.
        * The user should then enter a `<pin>` consisting of a four-digit
          number `[0-9][0-9][0-9][0-9]`.
        * If the PIN entered is invalid (not formatted correctly) or if
          it is unable to authenticate the user, then the program should
          print

              Not authorized

          and return to the ATM prompt (`ATM: `).
        * Otherwise, it should print

              Authorized

          and change the prompt to

              ATM (<user-name>):  

          Note the spacing at the end of the prompt.
 * `withdraw <amt>`
    * Inputs
       * `<amt>`: a non-negative integer `[0-9]+` at most what can be
         represented with an `int`.
    * Behavior
       * If not user is logged in, then print

             No user logged in

       * Otherwise, if the inputs to the command are invalid, then print

             Usage: withdraw <amt>

       * Otherwise, if the user has insufficient funds, then print

             Insufficient funds

       * Otherwise, if the user has sufficient funds, then print

             $<amt> dispensed

         and those funds should be subtracted from the logged-in
         user's balance.
       * If a user was logged in, then that user should stay logged in
         after this command.
 * `balance`
    * Behavior
       * If no user is logged in, then print

             No user logged in

       * Otherwise, if the inputs to the command are invalid, then print

             Usage: balance

       * Otherwise, if the user's current balance is `<balance>`, then print

             $<balance>

       * If a user was logged in, then that user should stay logged in after
         this command.
 * `end-session`

   This command represents the user terminating their session and logging
   out of the ATM.
    * Behavior
       * If no user is logged in, then print

             No user logged in

       * Otherwise, terminate the current session and print

             User logged out

         The ATM should then continue listening for further `begin-session`
         commands.
 * Any other commands are invalid (note that deposits are not supported
   at the ATM), and should result in printing

       Invalid command

 * **Note:** The ATM should support an unlimited number of `withdraw` and
   `balance` commands per session. Deposits at an ATM are not supported.

## Example transcript

Here is an example transcript, assuming Alice's balance is $100 (and this
balance is not modified at the bank during this execution), that the file
`Alice.card` is present, and that Alice's PIN is 1234 (continuing the
example from the `bank` program). Note the prompts, which change as a
user begins or ends a session:

    ATM: begin-session Aliceeee
    No such user
    
    ATM: begin-session Alice
    PIN? 1234
    Authorized
    
    ATM (Alice):  balance
    $100
    
    ATM (Alice):  withdraw 1
    $1 dispensed
    
    ATM (Alice):  balance
    $99
    
    ATM (Alice):  end-session
    User logged out
    
    ATM: balance
    No user logged in
    
    ATM: 