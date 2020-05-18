# Building the System

This document describes the various programs you will need to write for
this project. We have provided stub code for much of it, along with
some helper utility code (a hash table and a list). You are welcome to
use these, or to write your own, but the way that the code
communicates (the ATM and bank route their messages through the
router) must remain the same.

We also describe outputs for the program: make sure
that these match *exactly* (the outputs do not have periods at the
end, for instance) so that we can use automatic graders.

## Building the programs: what and how

From your submission directory, there should be a Makefile such that
when we run `make` it creates the following programs:

 * `bin/atm`
 * `bin/bank`
 * `bin/init`
 * `bin/router`

The `atm`, `bank`, and `router` programs must be implemented in
C. `init` can be a script or a C program. The stub code that we
provide contains the networking operations you will need. The router,
bank, and ATM all run on different ports on `localhost` (so you need
not even be connected to the Internet for this to work).

Your submissions must build with stack guard turned off
(`-fno-stack-protector`) and executable stacks (`-z execstack`) -- as
already specified in the Makefile provided. As you all know, this is
bad practice, and you should not do this outside of this class! But
it will require you to be all the more on your toes--and should make the
break-it phase of the project even more fun.

## Invoking the programs

The `init` and `router` programs can be run in either order, but both
must be run before `bank`, which in turn must be run before `atm`. The
order of these will be clear from what they create.

 * The `init` program is described in [init.md](init.md).
 * The `bank` program is described in [bank.md](bank.md).
 * The `atm` program is described in [atm.md](atm.md).

## Threat model

Your protocol should be secure against an adversary who is not in
possession of a user's ATM card, even if the adversary knows the
user's PIN, and vice versa. The attacker is also in control of a
router on the path between the ATM and the bank, and can inspect,
modify, drop, and duplicate packets--as well as create wholly new
packets--to both ATM and bank.

However, we assume that the bank computer cannot be compromised,
nor can the memory on the ATM be examined. In particular, you do
*not* need to defend against the following:

 1. Using code disassembly to recover secret keys, or
 2. Attacks that require restarting the bank, or
 3. Attacks that involve inspecting the contents of the files
    created by the `init` program: this of these like secret
    information that a bank operator inputs at the bank server
    and when installing the ATM (though, again, the specific
    contents of these files are purely up to you).

## Deliverables

Submissions must be to your **team** repository (even if you are
working solo).

Submit your implementation (all of the `.c` and `.h` files that
collectively encompass your code, including any files we provided,
even if you do not modify them), along with a Makefile. Building
all of your executables should require only running "`make`". We
have provided an initial Makefile; modify this as necessary (or
make your own). In addition to the implementation, you must write
a *design document* in which you:

 1. Describe your overall protocol in sufficient detail for a
    reader to understand the security mechanisms you put into
    place, without having to look at the source code. This must
    include the format of the files you create (with the `init`
    and `bank` programs) and the messages you send between the
    ATM and bank.
 2. List, one by one, the specific attacks that you have considered
    and describe how your protocol counters these threats. This is
    critical for how we will be grading this part of the project
    (see Grading below).
 3. You can also mention threats that you chose to ignore because
    they were unimportant, as well as threats that were important
    but you were unable to address.

**This must be submitted in a sane format: plain text (including markdown),
ps, or pdf.**

## Grading

Part 1 will be worth 100 points and will be graded as follows: 25% of
the grade will be based on automated tests that your submission achieves
the basic functionality (e.g., proper account balances, not permitting
withdrawals with insufficient funds, etc.). The remaining is based on
your protocol's ability to protect against attacks.

Each distinct attack and countermeasure you present in your design
document is an additional 15%. ("Distinct" here is pretty loose: it
doesn't mean that, e.g., all confidentiality attacks are equivalent,
but rather that the attacks are morally different. For example, if
there is a vulnerability such that modifying a part of a packet to
some number *x* causes the user to withdraw *$x* instead of their
intended amount, then exploiting that vulnerability with
*x*=$200 and *x*=$300 are fundamentally the same attack.) You *must*
list the attacks and countermeasures one-by-one in your document to
make it clear for grading. You may include additional attacks beyond
the 5 required for full credit. While this will not increase your
score, the more attacks you prevent, the greater your chances of
surviving the break-it phase of the project.

If your design document does not correspond to your implementation,
you will be given no credit--if you are not able to implement some
feature that you think should be present, feel free to describe it
so long as you state clearly that it is not implemented; for
well-described attacks and designs without implementation, partial
credit will be available.
