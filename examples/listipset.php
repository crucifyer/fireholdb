<?php

if(!isset($_SERVER['argv'][1])) die("php example.php ipaddr\n");

include_once '../src/fireholdb.class.php';
$firehol = new fireholdb();
print_r(
	$firehol->listIpset($_SERVER['argv'][1])
);
exit(0);

