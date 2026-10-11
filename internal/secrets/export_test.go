package secrets

// SetGeteuidForTest replaces the effective-UID lookup used by the master key
// owner check and returns a function that restores it.
func SetGeteuidForTest(f func() int) (restore func()) {
	old := geteuid
	geteuid = f
	return func() { geteuid = old }
}

// SetSyncDirForTest replaces the directory sync of the master key file (AUD-20) and returns a
// function that restores it.
func SetSyncDirForTest(f func(dir string) error) (restore func()) {
	old := syncDir
	syncDir = f
	return func() { syncDir = old }
}

// SealBackupKeyForTest wraps priv under Argon2id(passphrase) with the v2 AAD of pub and senderPub, exactly as
// NewBackupKey does, but with any private key (TestUnwrapChecksThePublicKey).
func SealBackupKeyForTest(passphrase []byte, p KDFParams, priv, pub, senderPub []byte) (WrappedBackupKey, error) {
	return wrapBackupKey(passphrase, p, priv, pub, senderPub)
}

// SealBackupKeyRawForTest wraps priv under Argon2id of the passphrase bytes exactly as given, without the NFKC step:
// a record as the code before the I-1 fix wrote it (setup normalised before calling NewBackupKey).
func SealBackupKeyRawForTest(passphrase []byte, p KDFParams, priv, pub, senderPub []byte) (WrappedBackupKey, error) {
	return sealBackupKey(passphrase, p, priv, pub, senderPub)
}
