# fireholdb
search firehol blocklist ip database with sqlite

* firehol project https://github.com/firehol/blocklist-ipsets

```bash
# first time
$ php createdb.php /projects/firehol/blocklist-ipsets/
```

```php
<?php
 
 include_once 'fireholdb.class.php';
 $firehol = new fireholdb();
 print_r(
 	$firehol->findip('172.217.24.142') // google.com
 );
```
```
Array
(
    [0] => stdClass Object
        (
            [ip] => 172.208.0.0/12
            [ipset] => id_continent_na
            [category] => geolocation
        )

    [1] => stdClass Object
        (
            [ip] => 172.216.0.0/15
            [ipset] => id_country_us
            [category] => geolocation
        )

    [2] => stdClass Object
        (
            [ip] => 172.217.0.0/16
            [ipset] => continent_na
            [category] => geolocation
        )

    [3] => stdClass Object
        (
            [ip] => 172.217.0.0/16
            [ipset] => country_us
            [category] => geolocation
        )

    [4] => stdClass Object
        (
            [ip] => 172.217.0.0/19
            [ipset] => ip2location_continent_na
            [category] => geolocation
        )

    [5] => stdClass Object
        (
            [ip] => 172.217.0.0/19
            [ipset] => ip2location_country_us
            [category] => geolocation
        )

    [6] => stdClass Object
        (
            [ip] => 172.217.24.128/27
            [ipset] => ipip_continent_as
            [category] => geolocation
        )

    [7] => stdClass Object
        (
            [ip] => 172.217.24.128/27
            [ipset] => ipip_country_jp
            [category] => geolocation
        )

)

```
