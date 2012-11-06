keePassPHP
==========

This is a port of KeePass Password Safe (cf http://keepass.info) in PHP. It addresses the problem of accessing one's KeePass password database through the Internet, even on another machine than one's, where KeePass is not installed. It provides an easy, simple management of several KeePass password databases, enabling to open them to extract list of entries and passwords from it. It does not aim at replacing KeePass, so does not provide features like adding new entries, etc. Just opening databases to find entries and password, in an easy but as secure as possible.

What can it do for now ?
========================

For now, KeePassPHP can open KeePass 2.x databases only, encoded with default parameters (AES encryption, Salsa20 stream-cipher, plain or gzip compression), and with a master key including only passwords and key files (all the key files format should be supported). It is able to extract a list of entries from it, keeping only some basic information like the title, url, username, icon and tags ; it can also extract the passwords.

How it works
------------

Every managed KeePass database file is stored on the server running KeePassPHP, as well as the possible key files. A stored KeePass database file can be accessed through an ID, chosen when the database is added to KeePassPHP; that ID also makes it possible to find the key files which are associated to that KeePass database, so that when the user want to open its database, he has to give the ID of that database, and the textual passwords; KeePassPHP will rebuild the master key from them and from the stored key files.

More precisely, KeePassPHP keeps a (text-based) database of all the password databases ID it knows, with the name of the corresponding database file, the key files, the scheme of the master key (password and/or key file), and *if the user agrees*, some not-too-sensitive information about the entries (title, username, url, icon) to avoid having to decrypt the database twice to find one password (once to find the list of entries and displaying it, plus another time to find a password). For KeePass 2.x databases, decrypting may be quite expensive, and limiting the number of times a database is decrypted might be a good idea. It is important to notice that all these non-too-sensitive information that can be accessed with an ID are also encrypted (but with a weaker brute-force protection than the password database itself, to make it far less expensive to compute) ; the encryption key may be the same than the one of the database, or another, different one (in which case you will need two passwords to access your database with KeePassPHP: one to decrypt the internal KeePassPHP database, and one to decrypt the actual KeePass passwords database).

ID can be anything, they do not need to be secure since they are not passwords but just ways of identifying databases to make it possible to manage several ones. Actually, the sha1 of the ID is computed, and this sha1 is used as a key to find the database. Since people usually have only one password database, an ID can be seen as an username.


Security
--------

KeePassPHP makes the server running it be like another machine with KeePass, with copies of the key files and the password database file. Except that it may be reachable from anywhere on the earth, without physical access. But it is not necessarily easier to break into your server than into your computer...
However, it is true that if you have a web access to your password database, anyone on the Internet could also have it, if they know the password. This is more or less unavoidable if you want a web access (i.e if you want to use something like KeePassPHP), so the security of your passwords might be a bit lowered (in the sense that someone who knows your password will no longer have to find an access to your database file also ; they will still have to find your ID, though).

Another more or less unavoidable problem is that you will want to use KeePassPHP on computers that are not yours. If there is something like a keylogger on these computers, your password will get sniffed. Big problem ! This might be slightly overcome by using more secure authentication schemes (e.g a two-factor scheme, with an email for example, but that would require you to have an actual access to your mails, wich might be a bit tricky if you need a password for that...)(having something like a virtual keyboard could also bring more security... at some extent), but this is not implemented yet, and I doubt it will ever be as secure as using KeePass on one's own machine. So just use it on computers that are not yours, but that you know you can trust... and/or only if you really need it (that might happen).


Requirements
------------

This should work with PHP 5.2 and higher, with some common hash and crypto libraries like mcrypt.

TODO
====

- Adding a **full** support of KeePass 2.x databases, especially for the ARC4 StreamCipher which is not usable yet.
- Adding a way to use remotely stored databases or key files (or syncing with them), e.g stored on DropBox, on other servers, maybe as a temporary uploaded file, etc.
- Making it possible for the user to select the information it accepts to be stored by KeePassPHP outside the KeePass database (for now it is either everything (titles, usernames, url, icons), or nothing).
- Adding more secure authenticating ? (e.g two-factor authentication, ...)
- For now, only KeePass 2.x databases are (partly) handled. Adding a support for KeePass 1.x databases may be a good idea.

License
=======

This work is MIT licensed.