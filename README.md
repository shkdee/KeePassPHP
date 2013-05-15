KeePassPHP
==========
This is a port of KeePass Password Safe (cf http://keepass.info) in PHP. Its motivation is to make it possible to access one's KeePass password database through the internet; it provides an easy, simple management of several KeePass password databases, enabling to open them to extract list of entries and passwords. It does not aim at replacing KeePass, so does not provide features like adding new entries, etc. Just opening databases to find entries and password, in an easy but as secure as possible.

How to use it ?
--------------------
Just include the file "keepassphp.php" in your client application, and call before everything else the method `KeePassPHP::init()`. The class KeePassPHP exposes all the needed methods to manage KeePass databases. See the project "KeePassPHP-UI" to have an example of how to use them.

KeePassPHP will store database files in the directory `keepassphp/data/secure/kdbx`, key files in the directory `keepassphp/data/secure/key` and internal sensitive information in the directory `keepassphp/data/secure/kphpdb` ; it will create them if they do not exist, with reading and writing permissions only for the owner of PHP process. But if they already exist, make sure that they are not readable for everyone ; normally, only PHP should be able to read or write to these directories. The whole directory `keepassphp/data/secure` can be made accessible only to PHP.

What can it do for now ?
--------------------------------
For now, KeePassPHP can open KeePass 2.x databases only, encoded with default parameters (AES encryption, Salsa20 stream-cipher, plain or gzip compression), and with a master key including only passwords and key files (all the key files format should be supported). It is able to extract the passwords (of all entries or of a given entry), and to keep separately for an easier and quicker access the list of entries with only some basic information like the title, url, username, icon and tags.

How it works
-----------------
When you add a KeePass database file to KeePassPHP, you have to chose an ID that will be associated to the database file ; the file is then stored on the server, as well as the possible key files. They can only be retrieved from the chosen ID ; so that when an user want to open its database, they have to give the ID of this database, and the textual password key ; KeePassPHP will then build the master key from this password key and the possible stored key file, and decrypt the database file.

To retrieve the files from the ID, KeePassPHP keeps a (encrypted text-based) database of all the password databases ID it knows, with the name of the corresponding database file, the key files, the scheme of the master key (password and/or key file), and *if the user agrees*, some not-too-sensitive information about the entries (title, username, url, icon) to avoid having to decrypt the database twice to find one password (once to find the list of entries and displaying it, plus another time to find a password). The motivation for this last point stems from the fact that for KeePass 2.x databases, decrypting the file may be quite time-consuming because of the numerous decryption operations that are generally needed and because PHP is not that performant, so limiting the number of times a database is decrypted may be a good idea. Besides being not-too-sensitive, this information kept internally by KeePassPHP is also encrypted (but with a weaker brute-force protection than the password database itself, to make it far less expensive to compute) ; the encryption key may be the same than the one of the database, or another, different one (in which case you will need two passwords to access your database with KeePassPHP: one to decrypt the internal KeePassPHP database, and one to decrypt the actual KeePass passwords database).

An ID can be anything, it does not need to be secure since it is not a password, but just a way to identify a database, to make it possible to manage several ones. The password corresponding to an ID is the password used to encrypt the internal KeePassPHP data that this ID enables to retrieve. Since people usually have only one password database, an ID can be seen as an username.


Security concerns
------------------------
From the moment you want to be able to access your password database from the Internet with no other secret than a password, you lower the security of the system, since having a physical access to one of your machines is no longer needed to try to access your password database.
However, breaking into your server may not be easier than into your computer, so the access you enable with KeePassPHP is only open through KeePassPHP itself, which greatly limits the possibilities of brute force attacks (if your password is strong enough).

Another security problem is that KeePassPHP is useful to be accessed on computers that are not your; but if there is something like a keylogger on these computers, your password will get sniffed... This problem might be partly addressed through the use of more secure authentication scheme (e.g two-factor scheme or virtual keyboard), but this is not implemented yet ; and regardless of the authentication scheme, I doubt that using KeePassPHP will ever be as secure as using only KeePass, only on your own machine.

Being aware of these security problems is important before using KeePassPHP. They does not mean that you should not using it, but that you should take care of:
* using a strong password for your password database, since it is the only remaining protection;
* not using KeePassPHP on computers you cannot trust; but on the computers of your family members, relatives or close friends, for examples, there should be no problem.

Requirements
------------------
This should work with PHP 5.2 and higher, with some common hash and crypto libraries like mcrypt.

TODO
-----
- Adding a **full** support of KeePass 2.x databases, especially for the ARC4 StreamCipher which is not usable yet.
- Adding a way to use remotely stored databases or key files (or syncing with them), e.g stored on DropBox, on other servers, maybe as a temporary uploaded file, etc.
- Making it possible for the user to select the information it accepts to be stored by KeePassPHP outside the KeePass database (for now it is either everything (titles, usernames, url, icons), or nothing).
- Adding more secure authenticating ? (e.g two-factor authentication, ...)
- For now, only KeePass 2.x databases are (partly) handled. Adding a support for KeePass 1.x databases may be a good idea.

License
-------
This work is MIT licensed.
