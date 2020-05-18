# ATM Design and Implementation

This is a two-part project, the first of which is a *team* effort,
while the second is an *individual* effort. Because the second part of
the project will make use of the results of the first part, there will
not be extensions granted. The second part is due at the end of the
semester, so extensions cannot be granted.

In this project you will first design and implement a prototype
ATM/Bank system. Then you will get a chance to (try to) attack other
teams' designs! We have tried to make these instructions as explicit
as possible. Read them carefully; *if anything is unclear, please ask
for clarification well in advance.*

## Overview

 1. You may work in teams of at most four people. Sign up for your
    teams on ELMS under "People">"Groups".

 2. You will design and implement three programs: an *ATM*, a *bank*,
    and an *init* program that initializes state for them. (You may
    also find it useful to create various auxiliary files defining
    classes and functionalities that can be used by the ATM and Bank
    classes.)

 3. You will be provided with stub code for the ATM, the bank, and a
    *router* that will route messages between the ATM and the bank. The
    stub code will allow the ATM and the router to communicate with each
    other, and the router and the bank to communicate with each other.
    The router will be configured to simply pass messages back-and-forth
    between the ATM and the bank. (Looking ahead, the router will provide
    a way to carry out passive or active attacks on the "communication
    channel" between the bank and the ATM.)

 4. You will design a protocol allowing a user to withdraw money from
    the ATM.  Requirements include:
    
     * The ATM *card* of user `XXX` will be represented by a file
       called `XXX.card`.
     * The user's PIN must be a 4-digit number.
     * User balances will be maintained by the bank, not by the ATM.
     * You need **not** support multiple ATMs connecting to the bank
       simultaneously.
     * You also do **not** need to maintain state between restarting
       the bank (e.g., all user balances can be maintained in memory).
    
    Of course, as part of the design process you will want to consider
    security...

 5. You will then implement your protocol. Most of your work should
    involve the ATM, bank, and init programs, with no (or absolutely
    minimal) modifications to the router.

 6. As with previous projects, the reference platform is the `baseline`
    docker image. At this point, you should be able to create your own
    scripts to build and run in a container using this image.

Part 1, the team phase of the project, is described in
[build-it.md](build-it.md).

Part 2, the solo phase of the project, is described in
[break-it.md](break-it.md).
