#!/usr/bin/env php
<?php

# Install/require composer deps
if (! is_dir(__DIR__.'/vendor/phpseclib')) {
    system('php -r "readfile(\'https://getcomposer.org/installer\');" | php', $rc);
    die_if('Could not download composer', $rc != 0);

    system(__DIR__.'/composer.phar install', $rc);
    die_if('Could not install composer dependencies', $rc != 0);
}
require_once __DIR__.'/vendor/autoload.php';

# Exploits to test for
$exploits = array(
    'Exploit 1 (CVE-2014-6271)' => array(
        'test' => 'env x=\'() { :;}; echo vulnerable\' bash -c "echo this is a test"',
        'output' => 'vulnerable',
    ),
    'Exploit 2 (CVE-2014-7169)' => array(
        'test' => 'env X=\'() { (shellshocker.net)=>\\\' bash -c "echo date"; cat echo ; rm -f echo',
        'output' => '\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w{3} \d{4}',
    ),

    'Exploit 3 (???)' => array(
        'test' => 'env -i X=\' () { }; echo hello\' bash -c \'date\'',
        'output' => '\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \w{3} \d{4}',
        // Sun Sep 28 21:57:51 CDT 2014
    ),

    'Exploit 4 (CVE-2014-7186)' => array(
        'test' => 'bash -c \'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF\' ||'."\n".'echo "CVE-2014-7186 vulnerable, redir_stack"',
        'output' => 'CVE-2014-7186 vulnerable, redir_stack',
    ),

    'Exploit 5 (CVE-2014-7187)' => array(
        'test' => '(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash ||'."\n".'echo "CVE-2014-7187 vulnerable, word_lineno"',
        'output' => 'CVE-2014-7187 vulnerable, word_lineno',
    ),
);

# Package managers to test for
$package_managers = array(
    'yum' => 'yum update bash -y',
    'apt-get' => 'apt-get -qq update; apt-get -qq -y install bash',
    'pacman' => 'pacman -Syu',
);

# Print usage if no input file provided
if (count($argv) < 2) {
    $msg = <<<USAGE

USAGE: $argv[0] <credentials>

credentials: file containing comma- or tab-separated values of:
  * hostname/ip
  * ssh username (with sudo permission, preferably)
  * ssh password
  * root password for su access (if ssh user has no sudo permission)

USAGE;
    die($msg);
}
else {
    define('CREDS_FILE', $argv[1]);
}

# Detect comma- or tab-separated by file extension
if (substr(CREDS_FILE, -4) == '.tsv') {
    define(CREDS_DELIMITER, "\t");
}
elseif (substr(CREDS_FILE, -4) == '.csv') {
    define(CREDS_DELIMITER, ",");
}
else {
    die('Provided file must be comma-separated (.csv) or tab-separated (.tsv): '.CREDS_FILE);
}

# Estimate rows in file
$total = count_rows(CREDS_FILE);
announce("Estimated $total rows in ".CREDS_FILE."\n");

# Attempt patching of each entry
if (($fh = fopen(CREDS_FILE, 'r')) !== FALSE) {
    $i = 1;
    while (($row = fgetcsv($fh, 5000, CREDS_DELIMITER)) !== FALSE) {
        announce("\nProcessing {$i} of {$total}");
        attempt_patch($row);
        $i++;
    }
    fclose($fh);
}

announce('Complete!');

## Reusable functions -- should be abstracted into a class, with fewer globals

function die_if ($msg, $test) {
    if ($test) {
        file_put_contents('php://stderr', $msg, FILE_APPEND);
        exit(1);
    }
}

function announce ($msg, $newline = true) {
    echo $msg . ($newline ? "\n" : '');
}

function stamp_log ($msg) {
    global $current_host;

    if (! isset($current_host)) {
        $current_host = 'localhost';
    }

    # stamp each line of message with hostname
    $msg = str_replace("\n", "\n[{$current_host}] ", str_replace("\r", '', $msg));
    file_put_contents('php://stderr', "[{$current_host}] $msg\n\n", FILE_APPEND);
}

function count_rows ($filename) {
    $linecount = 0;
    $fh = fopen($filename, "r");
    while(! feof($fh)){
      $line = fgets($fh);
      if (! empty($line)) {
          $linecount++;
      }
    }
    fclose($fh);

    return $linecount;
}

function ssh_connect ($hostname, $username, $password) {
    global $current_host;

    $ssh = new Net_SSH2($hostname);
    $out = $ssh->login($username, $password);
    $ssh->setTimeout(5);

    if (!$out) {
        announce("Connection to $username @ $hostname failed\n");
        return;
    } else {
        $current_host = $hostname;
        announce("Connected as $username @ $hostname!\n");
        return $ssh;
    }
}

function ssh_assert ($ssh, $pattern, $msg, $disconnect = true, &$matches = array()) {
    $out = $ssh->read($pattern, NET_SSH2_READ_REGEX);
    stamp_log($out);
    if (!preg_match($pattern, $out, $matches)) {
        if ($disconnect) {
            ssh_disconnect($ssh, $msg);
        }
        return;
    }
    return true;
}

function ssh_root ($ssh, $username, $password, $rootpass) {
    if ($username != 'root') {
        if (! empty($rootpass)) {
            $ssh->write("su -\n");
            if(!ssh_assert($ssh, '![Pp]assword[^:]*:!', 'Attempted su to root')) return;

            $ssh->write("$rootpass\n");
            if(!ssh_assert($ssh, '![#] $!', 'Sent root password')) return;
        }
        else {
            $ssh->write("sudo -s\n");
            if(!ssh_assert($ssh, '![Pp]assword[^:]*:!', 'Attempted sudo -s')) return;

            $ssh->write("$password\n");
            if(!ssh_assert($ssh, '![#] $!', 'Sent ssh password')) return;
        }

        # Verify successfully rooted
        $ssh->write("whoami\n");
        if(!ssh_assert($ssh, '!root!', 'Expected to be root')) return;

        announce("Gained root!\n");
        return $ssh;
    }
}

function ssh_disconnect ($ssh, $msg = "Disconnected") {
    global $current_host;
    $ssh->disconnect();
    stamp_log($msg);
    unset($ssh, $current_host);
}

function test_vulns ($ssh) {
    global $exploits;

    $vulns = array();

    foreach ($exploits as $name => $exploit) {
        announce("Testing for {$name}...", false);
        $token = substr(sha1(microtime()), 0, 5);
        $ssh->write("{$exploit['test']}; echo {$token}\n");
        if(ssh_assert($ssh, "!{$token}[\S\s]*?{$exploit['output']}!", null, false)) {
            $vulns[] = $name;
            announce("ALERT: Vulnerable to $name");
        }
        else {
            announce("YAY: Not vulnerable to $name");
        }
    }

    return $vulns;
}

function attempt_patch ($row) {
    global $current_host;
    global $exploits;
    global $package_managers;

    # Trim credentials before use
    $hostname = trim($row[0]);
    $username = trim($row[1]);
    $password = trim($row[2]);
    $rootpass = trim($row[3]);

    $ssh = ssh_connect($hostname, $username, $password);
    if(!ssh_assert($ssh, '![$#] $!', 'Expected $ or # prompt')) return;

    # Test for vulns before rooting
    $vulns = test_vulns($ssh);
    if (empty($vulns)) {
        announce('No shellshock vulnerabilities found!');
        ssh_disconnect($ssh);
        return;
    }

    # Root before patching attempt
    $ssh = ssh_root($ssh, $username, $password, $rootpass);
    if (!$ssh) return;

    # Determine which if any pkg manager is available
    foreach ($package_managers as $bin => $command) {
        # Workaround for return codes on ssh->read/write
        $ssh->write("command -v {$bin}; echo return_code:\$?\n");
        ssh_assert($ssh, '!return_code:(\d+)!', 'Expected return_code', false, $rc);

        if ($rc[1] == '0') {
            announce("Attempting bash upgrade with {$bin}");
            $ssh->setTimeout(false);
            $ssh->write("{$command}; echo return_code:\$?\n");
            ssh_assert($ssh, '!return_code:(\d+)!', 'Expected return_code', false, $rc);
            $ssh->setTimeout(5);
            if ($rc[1] == '0') {
                announce("Bash upgrade with {$bin} apparently successful!");
            }
            break;
        }
    }

    # Test vulns once more
    ssh_disconnect($ssh);
    $ssh = ssh_connect($hostname, $username, $password);
    if(!ssh_assert($ssh, '![$#] $!', 'Expected $ or # prompt')) return;

    $vulns = test_vulns($ssh);

    if (empty($vulns)) {
        announce('No shellshock vulnerabilities found!');
        ssh_disconnect($ssh);
        return;
    }

    # TODO: implement build and install from source, if vulns still present

    ssh_disconnect($ssh);
}
