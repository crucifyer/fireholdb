CREATE TABLE fireholdb (
fip TEXT NOT NULL,
mask TINYINT NOT NULL,
ipset TEXT NOT NULL,
category TEXT NOT NULL,
PRIMARY KEY (fip, mask, ipset)
);

CREATE INDEX fireholdb_ipset_dex ON fireholdb (ipset);
