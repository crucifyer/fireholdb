<?php

if(!isset($_SERVER['argv'][1])) die("php example.php ipaddr\n");

include_once '../src/fireholdb.class.php';
$firehol = new fireholdb();
echo $firehol->ipHasCategory($_SERVER['argv'][1]) ? 'need block' : 'fine', "\n";
exit(0);

