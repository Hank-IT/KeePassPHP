KeePassPHP
==========

![](https://github.styleci.io/repos/285295115/shield)

KeePassPHP is a pure-PHP library that can read password databases generated by the password manager KeePass 2.x (.kdbx files). It reads groups, entries and passwords, and makes them easily accessible through a simple PHP API. Its aim is not (yet) to completely replace KeePass: it cannot modify kdbx files, it can just read them.

More generally, KeePassPHP can also encrypt and decrypt files in the same secure way as KeePass does (with integrity checks, brute-force-guessing protection, etc).

Examples
---------------------

See [KeePassPHP-UI](//github.com/shkdee/KeePassPHP-UI), a web user interface directly using KeePassPHP to list all entries of a kdbx file, and then extract selected specific passwords on demand. Otherwise, the file keepassphp-cli.php is a command-line interface for KeePassPHP that also shows how to use almost everything provided by this library.

Library usages
---------------------
KeePassPHP can be used at two levels.

At low-level, KeePassPHP exposes an API to decrypt and encrypt content with the same secure format as KeePass. This content can be an XML-formatted KeePass password database, but also any other kind of data. So KeePassPHP can be used as a simple and strong file encryption/decryption library. It also exposes an API to read kdbx password database content as a tree of PHP objects, providing easy and natural access to every entry stored inside the kdbx file.

At high-level, KeePassPHP can store kdbx files associated with a unique ID. This way, many users can store and access their password database easily, just with their ID and password. When used like this, KeePassPHP stores data internally in "kphpdb" files to associate each ID with a kdbx file and a possible key file, along with possibly more data to make it faster for users to access the list of entries of their kdbx files (see below).

Internal kphpdb files
---------------------

Decrypting a kdbx file is computationally expensive. Indeed, to prevent an attacker from guessing your main password through brute-force attack, KeePass repeatedly encrypts that password a great number of rounds, to make the whole decryption process artificially hard. Thus, finding the password by brute-force would take a very long time.

But since PHP can be quite slow, decrypting a kdbx file only once can actually take a long time. Moreover, you may have to decrypt a single database twice just to find one password: a first time to get the list of all entries and display them to the user, and a second time to actually get the chosen password (that is typically what happens with KeePassPHP-UI).

To try and fix this, KeePassPHP can extract from kdbx files a subset of the entries data, without passwords. This extracted, less-sensitive information is then encrypted again and stored alongside the actual kdbx file in what I called a kphpdb file. A kphpdb file is encrypted exactly like a kdbx file, but with a low number of encryption rounds, so that it is faster to decrypt. With this sytem, accessing the list of entries without passwords is fast; but getting a password is still as hard as before. kphpdb files are also used to store key files associated with kdbx files, when there are some.

Security concerns
---------------------

First of all, if you use KeePassPHP on a server that you access through the Internet, you obviously need to secure the communication pipe to that server, since your passwords will be sent back and forth inside that pipe. So you always need to use https to access KeePassPHP.

Then, since your password database will be stored on that server, it must be hard to break into this server and get the kdbx file itself. Ideally, as hard as it is to do so for your computer, or wherever your kdbx file is also stored (maybe your phone, your dropbox account, etc). Now, if your server is correctly configured, this should actually be okay.

Another security problem to be aware of is that when you access KeePassPHP on a device which is not yours (which is typically the kind of usage you may have of KeePassPHP), you never know how much you can trust this device. It can have a keylogger that could sniff your main password, it can register the passwords you will probably copy in the clipboard, etc. Never use KeePassPHP - or any other password manager for that matter - on a computer you cannot trust!

Finally, the idea of kphpdb files that are faster to decrypt than the real kdbx files can actually destroy the protection against brute-force password guessing. Indeed, if the *same* password is used to encrypt a kdbx file and its corresponding kphpdb file, it will be as easy to brute-force-guess that password as it is for the kphpdb file, which is by design easier than for the kdbx file. If different passwords are used, there is no risk, but then the user has to remember another password and that's not the spirit of a password manager. With KeePassPHP, if you use kphpdb files, you can choose to either use a completely different password, or to use only half of the kdbx file password to encrypt the kphpdb file. In the latter case, the other half of the password would still be hard to brute-force-guess.

Note that this last problem only regards main password guessing; an attacker can still try to decrypt the content of the kdbx file without guessing the text password, and the complexity of this task is unchanged by the kphpdb file.

API
---------------------

[to be documented; see examples]

Requirements
---------------------
The recommended environment to run KeePassPHP is PHP 5.4 and higher, with the rather common OpenSSL extension.

KeePassPHP should actually work with PHP 5.3 and higher, and can use the common crypto library mcrypt when OpenSSL is not available (or when the PHP version is lower than 5.4). But OpenSSL is much faster and more reliable than mcrypt, so it is strongly suggested to load it when using KeePassPHP. Moreover, with PHP 7.2 and higher, mcrypt is no longer included in PHP by default, so OpenSSL is actually required in this case.

Note that using very high-level crypto libraries like libsodium or NaCl is not possible for KeePassPHP (as I understand those libraries), because some very specific ciphers (AES 256, CBC and ECB) are required to decrypt the very specific format of kdbx files, and these ciphers are not exposed by those libraries.

License
---------------------
This work is MIT licensed.
