perl-mail-gpg-example
=====================

Overview

This script takes in an email message via stdin, extracts the email
message body using MIME::Parser and decrypts the message body using
Mail::GPG. The decrypted message body is returned as an array for
further processing.

Example:

On the receiving Linux mail server:

1. Install gnupg

2. Install the following Perl modules:
 - Mail::GPG
 - MIME::Parser

Note: you need to install the Perl module Event due to a missing dependency.

    sudo perl -MCPAN -e 'install Event Mail::GPG MIME::Parser'

3. Create a gpg key
 - http://www.madboa.com/geek/gpg-quickstart/

4. Import the key into gpg under the user account where this script will run.
    gpg --fast-import key.pub key.sec

5. Create a procmail rule and forward gpg encrypted messages to decrypt.pl

<pre><code>
# Example procmailrc rule
:0
* ^To: <username>@<domain>.<tld>
| /home/<username>/bin/decrypt.pl
</code></pre>

6. Edit decrypt.pl to do something with the returned array

You can test with something like:

    cat encrypted_email.eml | ./decrypt.pl
