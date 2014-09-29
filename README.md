# ShockTrooper

### What is this?

A quickly thrown together script -- based on information from Shellshocker.net -- to ssh into, detect, and patch shellshock vulnerabilities across a number of remote servers, with the built in package manager on each given server.

Currently supported:

* Debian/Ubuntu using `apt-get`
* Redhat/CentOS using `yum`
* Arch using `pacman` (**theoretical** support, not yet confirmed)

### Why build this?

Out of necessity. For anyone with a number of Linux based servers -- and of varying distros -- patching them all can be something of a nightmare.

### What are the prerequisites?

You will need a control system to run from, with PHP installed. I would recommend something *nix based.

The underlying [phpseclib](https://github.com/phpseclib/phpseclib) claims PHP 4 support, though I would recommend at least 5.1.0.

### How do I use it?

*Note: This is alpha code. Run at your own risk on production or mission critical sustems!*

First, collect your servers' login credentials in a  tab-separated (`*.tsv`) or comma-separated (`*.csv`) file, with each row in this order:

0. hostname / ip address (eg: `10.0.0.10`)
0. ssh username (eg: `jdoe`)
0. ssh password
0. root password (necessary only if ssh user does not have sudo permission)

Next, invoke the script and pass it said credentials file:

`php shocktrooper.php /home/me/servers.tsv`

All SSH activity will be output to STDERR, so you can redirect it to a log file if you just want to see the important bits:

`php shocktrooper.php /home/me/servers.tsv 2> ssh.log`

It will ssh into each server in turn, and test for known vulnerabilities. If any are found, it will attempt to upgrade bash with the system package manager. Afterward, it will test for said vulnerabilities once more.

You should end up seeing output like:

```
Estimated 1 rows in test.tsv


Processing 1 of 1
Connected as jdoe @ 10.0.0.10!

Testing for Exploit 1 (CVE-2014-6271)...ALERT: Vulnerable to  Exploit 1 (CVE-2014-6271)
Testing for Exploit 2 (CVE-2014-7169)...ALERT: Vulnerable to  Exploit 2 (CVE-2014-7169)
Testing for Exploit 3 (???)...ALERT: Vulnerable to Exploit 3 (???)
Testing for Exploit 4 (CVE-2014-7186)...ALERT: Vulnerable to  Exploit 4 (CVE-2014-7186)
Testing for Exploit 5 (CVE-2014-7187)...ALERT: Vulnerable to Exploit 5 (CVE-2014-7187)
Gained root!

Attempting bash upgrade with apt-get
Bash upgrade with apt-get apparently successful!
Connected as jdoe @ 10.0.0.10!

Testing for Exploit 1 (CVE-2014-6271)...YAY: Not vulnerable to Exploit 1 (CVE-2014-6271)
Testing for Exploit 2 (CVE-2014-7169)...YAY: Not vulnerable to Exploit 2 (CVE-2014-7169)
Testing for Exploit 3 (???)...ALERT: Vulnerable to Exploit 3 (???)
Testing for Exploit 4 (CVE-2014-7186)...YAY: Not vulnerable to Exploit 4 (CVE-2014-7186)
Testing for Exploit 5 (CVE-2014-7187)...YAY: Not vulnerable to Exploit 5 (CVE-2014-7187)
Complete!
```
