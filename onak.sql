DROP TABLE onak_keys;
DROP TABLE onak_uids;
DROP TABLE onak_sigs;

CREATE TABLE onak_keys (
	keyid	char(16) NOT NULL,
	keydata	oid NOT NULL,
	PRIMARY KEY (keyid)
);
CREATE INDEX onak_keys_keyid_index ON onak_keys(keyid);

CREATE TABLE onak_uids (
	keyid	char(16) NOT NULL,
	uid	varchar(6000) NOT NULL,
	pri	boolean,
	FOREIGN KEY (keyid) REFERENCES onak_keys
);

CREATE TABLE onak_sigs (
	signer	char(16) NOT NULL,
	signee	char(16) NOT NULL,
	FOREIGN KEY (signee) REFERENCES onak_keys
);
CREATE INDEX onak_sigs_signee_index ON onak_sigs(signee);
