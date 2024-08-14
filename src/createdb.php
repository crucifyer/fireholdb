<?php
/*
cd this/repository/src

# first time
git clone https://github.com/firehol/blocklist-ipsets.git /firehol/repository/blocklist-ipsets
php createdb.php /firehol/repository/blocklist-ipsets

# update
git pull
php createdb.php /firehol/repository/blocklist-ipsets

# use fireholdb.sqlite with fireholdb.class.php
*/

if(!isset($_SERVER['argv'][1]) || !is_dir($_SERVER['argv'][1])) die("php createdb.php fireholdir [dbfile]\n");
$update = true;
$binaryip = true;

$updatestamp = file_exists('updatestamp') ? file_get_contents('updatestamp') : 0;
$lastmtime = 0;
$db = new PDO('sqlite:'.($_SERVER['argv'][2] ?? __DIR__.'/fireholdb.sqlite'));
if(!$db->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name='fireholdb'")->fetch()) {
	$queries = preg_split('~;\s*~i', file_get_contents(__DIR__.'/schema.sql'), -1, PREG_SPLIT_NO_EMPTY);
	foreach($queries as $query) {
		$db->query($query);
	}
	$update = false;
}

dodir($_SERVER['argv'][1]);

$db->query("VACUUM");
echo "end\n";
file_put_contents('updatestamp', $lastmtime);
echo date("Y-m-d H:i:s\n", $lastmtime);
exit(0);

function dodir($of) {
	global $updatestamp, $lastmtime;

	$d = dir($of);
	while(false !== ($f = $d->read())) {
		if($f[0] == '.') continue;
		$fn = $of.'/'.$f;
		$mtime = filemtime($fn);
		$lastmtime = max($lastmtime, $mtime);
		if(preg_match('~\.(ip|net)set$~', $f) && $mtime > $updatestamp) {
			updateips($fn);
			continue;
		}
		if(is_dir($fn)) dodir($fn);
	}
	$d->close();
}

function updateips($f) {
	global $db, $update, $binaryip;
	$text = file_get_contents($f);
	$fips = preg_split('~[\r\n]+~', preg_replace('~^#.*$~m', '', $text), -1, PREG_SPLIT_NO_EMPTY);
	$comments = trim(preg_replace('~(?:^#(?:\s*$|\s?)|^.*$|\s+$)~m', '', $text));
	if(!preg_match('~^Category\s*:\s*(.*)$~m', $comments, $matches)) die("$f category not found\n");
	$category = trim($matches[1]);
	$ipset = preg_replace('~[\r\n].*$~s', '', $comments);

	$fields = [
		'ipset' => $ipset,
	];

	$db->beginTransaction();

	if(!count($fips)) {
		$db->prepare("DELETE FROM fireholdb WHERE ipset = :ipset")->execute($fields);
		$db->commit();
		echo "$ipset : $category - no data\n";
		return;
	}
	if($update) {
		$stmt = $db->prepare("SELECT * FROM fireholdb WHERE ipset = :ipset");
		$stmt->execute($fields);
		if($rows = $stmt->fetchAll(PDO::FETCH_OBJ)) {
			$oips = [];
			foreach($rows as $row) {
				$ip = inet_ntop($binaryip ? $row->fip : pack('H*', $row->fip));
				if($row->mask != 32) $ip .= '/' . $row->mask;
				$oips[] = $ip;
			}
			sort($fips);
			sort($oips);
			$fips = array_unique($fips);
			$oips = array_unique($oips);
			if(implode(',', $fips) == implode(',', $oips)) {
				echo "$ipset : $category - no update\n";
				$db->rollBack();
				return;
			}
			$db->prepare("DELETE FROM fireholdb WHERE ipset = :ipset")->execute($fields);
		}
	}

	$fields['category'] = $category;
	$ins = $db->prepare("INSERT INTO fireholdb (fip, mask, ipset, category) VALUES (:fip, :mask, :ipset, :category)");

	foreach($fips as $fip) {
		$ipmask = explode('/', $fip);
		$fields['mask'] = $ipmask[1] ?? 32;
		$fields['fip'] = $binaryip ? inet_pton($ipmask[0]) : unpack('H*', inet_pton($ipmask[0]))[1];
		$ins->execute($fields);
	}

	$db->commit();

	echo "$ipset : $category\n";
}
