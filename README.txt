ChangeCertAlias

The rationale for creating this dopey application stems from a recent
purchase of a code-signing certificate. After working through the formal
verification process (which is a very good thing), the code-signing certificate
finally arrived and had the following CA-generated alias:

   jim connors?s comodo ca limited id

The problem with this alias is the question mark character, which is actually
an alternative single quote character with an ordinal value of 0x2019.
It doesn't play particularly well with a Windows CMD.exe shell when
trying to represent non-ASCII characters on the command-line.

So why not just change the alias?

Normally, in the Java world if one wanted to modify a Java alias, one would
use the keytool(1) utility to accomplish that task.  Unfortunately trying
to find weird aliases like the one above using keytool(1) does not work well,
if at all, in the Windows CMD shell world.

This little utility solves the problem programmatically.  For an example
invocation, check out the SAMPLE_RUN.txt file.
