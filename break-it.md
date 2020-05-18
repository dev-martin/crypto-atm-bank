# Attacking Other Teams' Implementations

In the second phase of the project, you will *individually* evaluate
and attack another team's system. You get to select a target, but you
*may not* attack your own team's phase 1 submission.

When the break-it phase begins, all of the build-it repositories will
be made available for you to clone. You may find these at
https://gitlab.cs.umd.edu/search?utf8=%E2%9C%93&search=atm, which
should return a list of search results for repositories matching
"atm". Make sure you select one that is under `cmsc414-marsh/teams`.
If you want to download multiple potential targets before deciding on
one, we recommend doing it with a command like (for a hypothetical team
named "Gizmonic"):

    git clone https://gitlab.cs.umd.edu/cmsc414-marsh/teams/Gizmonic/atm Gizmonic

This will clone the target team's repository into a directory named
`Gizmonic`, rather than `atm`.

The next few steps must be done carefully. For exposition, we assume that
the team we are attacking is Gizmonic, cloned as above, and the attacker
is the student tservo.

 1. `cd Gizmonic` to work in the repository.
 2. Open the file `.git/config` in your favorite editor.
 3. Change the line

                url = https://gitlab.cs.umd.edu/cmsc414-marsh/teams/Gizmonic/atm.git

    to
    
                url = git@gitlab.cs.umd.edu:cmsc414-marsh/students/tservo/break-it.git

    Note that we are switching from an HTTPS URL to an SSH URL, so
    that we can push changes, and that we are now using tservo's
    existing `break-it` repository. Make sure you change the URL to
    use your repository, not tservo's. Save the file and quit the
    editor.
 4. Run the command:

        git push --force origin master

    This will replace the version of your `break-it` repository on gitlab
    with the local version. **You should almost never use the `--force`
    flag when pushing, because it will destroy whatever was in the remote
    repository!**
 5. Visit your newly-pushed `break-it` repository on https://gitlab.cs.umd.edu
    to verify that the push was successful.

## Rules of Engagement

In your attack, you may arbitrarily modify the router code and the
`*.card` files. A *successful attack* will be any attack that results
in a net outflow of money to the attacker. By way of illustration,
examples of successful attacks would be (but are not limited to):

 * Withdrawing any money from a user's account without access to their
   card file and/or PIN.
 * Withdrawing more money from a user's account than the balance permits.
 * Remotely depositing money into a user's account (*ie*, without accessing
   the bank's command line interface).
 * Learning a user's balance without having access to their card file
   and/or PIN.

Note that while you may not modify the bank or atm, you are welcome to
disable ASLR on your machine. Please indicate if your attack relies on this.

## Deliverables

In your `break-it` repository, create an `analysis` directory. *All of
your files for this part must be in this directory.*

Submit a vulnerability analysis of the implementation your attacked.
This analysis should describe your attack(s), if any, at both a high
level (so someone reading it can understand what you did) *as well as*
in sufficient detail to enable someone to replicate your attack. You
can also describe any vulnerabilities you were able to find but not
exploit (due to limitation of the project); e.g., and attack that would
require multiple ATMs to connect to the bank at once. If you were unable
to find any attack, simply explain what types of exploits you looked
for. *Your vulnerability analysis should begin with name(s) of the
students whose protocol you are attacking, and a 1-paragraph summary
of what attacks (if any) you were able to find.*

Submit your vulnerability analysis via git, in the usual way. This, too,
must be typeset in a sane format (plain text or markdown, pdf, or ps).
*In your analysis, please include the team name of whose project you
are attacking.*

You should also submit (in your git repository) any code you wrote to
implement your attack. This will likely include the modified router code,
but could include any other utilities you wrote as well. Make sure to
provide details on how to use your program(s) as part of your vulnerability
analysis.

## Grading

Part 2 is worth 20 points. A successful attack (that is also described
clearly in the vulnerability analysis) will automatically be awarded 20
points. Even if you are not able to find a successful attack, you can
still get points by

 1. pointing out potential vulnerabilities that your were not able
    to successfully exploit, and/or
 2. writing a good vulnerability analysis that outlines the exploits
    you looked for and argues why they are not present in the
    implementation you were attacking.

I reserve the right to award *extra* points for multiple attacks, or
particularly clever attacks, so be creative!
