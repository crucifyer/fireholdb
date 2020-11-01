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

	private function resultSet($rows) {
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

	public function findip($ip) {
		$binds = [];
		$stmt = $this->db->prepare($this->makeQuery($ip, $binds));
		$stmt->execute($binds);
		if(!($rows = $stmt->fetchAll(PDO::FETCH_OBJ))) return false;
		return $this->resultSet($rows);
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

	public function listIpset($ipset) {
		$binds = ['ipset' => $ipset];
		$stmt = $this->db->prepare("SELECT * FROM fireholdb WHERE ipset = :ipset ORDER BY fip");
		$stmt->execute($binds);
		if(!($rows = $stmt->fetchAll(PDO::FETCH_OBJ))) return false;
		return $this->resultSet($rows);
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
		$ipmask = explode('/', $ip.'/32');
		$res = [[self::$binaryip ? inet_pton($ipmask[0]) : unpack('H*', inet_pton($ipmask[0]))[1], $ipmask[1]]];
		for($i = 3; $i < $ipmask[1]; $i ++) {
			$res[] = [self::setmask($ipmask[0], $i), $i];
		}
		return $res;
	}

}
