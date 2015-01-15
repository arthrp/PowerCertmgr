# PowerCertmgr

A fork of **certmgr** utility from Mono tools. Allows user to manage certificates on a particular machine.
See [man page](http://linux.die.net/man/1/certmgr) for more details of the original utility.

However, original implementation has some known bugs (e.g. [it's easy to crash it](https://bugzilla.xamarin.com/show_bug.cgi?id=3516) - unfixed as of 15.01.2015), could have better code (e.g. variable naming, unused variables, etc) and IMO isn't really
 user-friendly.

I think that fundamental problem is that the original utility is bundled with Mono and pull-request approval process
there is quite long. So, inspired by new .NET modular structure, I created this fork.

Currently it's the original code, fixed to run in standalone with minor fixes (e.g. variables renaming).