<?php

class fireholdb
{
	static $binaryip = true;
	private $db;

	public function __construct($binaryip = true) {
		$this->db = new PDO('sqlite:'.__DIR__.'/fireholdb.sqlite');
		$this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		self::$binaryip = $binaryip;
	}

	private function makeQuery($ip, &$binds) {
		$where = [];
		$masksets = self::makeMaskSet($ip);
		foreach($masksets as $maskset) {
			$binds[] = self::$binaryip ? $maskset[0] : unpack('H*', $maskset[0])[1];
			$where[] = "fip = ? AND mask = {$maskset[1]}";
		}
		return "SELECT * FROM fireholdb WHERE ((".implode(") OR (", $where)."))";
	}

	public function findip($ip) {
		$binds = [];
		$stmt = $this->db->prepare($this->makeQuery($ip, $binds));
		$stmt->execute($binds);
		if(!($rows = $stmt->fetchAll(PDO::FETCH_OBJ))) return false;
		$res = [];
		foreach($rows as $row) {
			$res[] = (object)[
				'ip' => inet_ntop(self::$binaryip ? $row->fip : pack('H*', $row->fip)).'/'.$row->mask,
				'ipset' => $row->ipset,
				'category' => $row->category
			];
		}
		return $res;
	}

	public function ipHasCategory($ip, $categories = ['abuse', 'anonymizers', 'attacks', 'malware', 'reputation', 'spam']) {
		// abuse, anonymizers, attacks, malware, reputation, spam, geolocation, organizations, unroutable
		$binds = [];
		$query = $this->makeQuery($ip, $binds);
		$query .= " AND category IN ('".implode("','", (array)$categories)."') LIMIT 1";
		$stmt = $this->db->prepare($query);
		$stmt->execute($binds);
		return $stmt->fetch() ? true : false;
	}

	public function ipGetCategories($ip, $categories = []) {
		$binds = [];
		$query = $this->makeQuery($ip, $binds);
		if(count($categories)) {
			$query .= " AND category IN ('".implode("','", (array)$categories)."')";
		}
		$stmt = $this->db->prepare($query);
		$stmt->execute($binds);
		if(!($rows = $stmt->fetchAll(PDO::FETCH_OBJ))) return false;
		$res = [];
		foreach($rows as $row) {
			$res[] = $row->category;
		}
		return $res;
	}

	public static function setmask($ip, $mask) {
		$ip = inet_pton($ip);
		$len = strlen($ip);
		$pos = (int)floor($mask / 8);
		$bitwise = $mask % 8;

		if($bitwise) {
			$ip[$pos] = chr(ord($ip[$pos]) & (255 - (pow(2, 8 - $bitwise) - 1)));
		} else $pos --;
		for($i = $pos + 1; $i < $len; $i ++) {
			$ip[$i] = "\x00";
		}
		return $ip;
	}

	public static function makeMaskSet($ip) {
		$res = [[self::$binaryip ? inet_pton($ip) : unpack('H*', inet_pton($ip))[1], 32]];
		for($i = 3; $i <= 31; $i ++) {
			$res[] = [self::setmask($ip, $i), $i];
		}
		return $res;
	}

}
