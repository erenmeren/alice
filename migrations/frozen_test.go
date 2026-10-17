package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"alice/migrations"
)

// frozen holds the SHA-256 of every migration that shipped in a release candidate. An installed
// database has already run these files; editing one changes nothing there and makes a fresh install
// differ from an upgraded one.
var frozen = map[string]string{
	"00001_init.sql":                      "24d05ba49fc6b893fbfd15d740a1de9e9262f7a94be6b9f27fc06c4865003d27",
	"00002_core.sql":                      "f3a0de5b1f96a8a824a585de16adb29c0013fd72997540309af5c5696df7d323",
	"00003_license.sql":                   "43125f7b2d31164ada71eb03bd2c6e8c63b2080849b1dfc558c13a666f200f71",
	"00004_license_installation_seal.sql": "9ab7e041782046631a8bacd8d643449a67b6cde38013285370e190f4a2f18a5b",
	"00005_inventory_jobs.sql":            "5ee4d8a7137199448e953a7a06dd1526b258c716743f61fe639bb29e3ef9dcb7",
	"00006_certificates.sql":              "e4200d283a8c6ce6b7c9ae2cd079cbc2547a1d6e8c9741404bc1adb2387e139c",
	"00007_license_seal_read_only.sql":    "f61b5164c719687f30216bad4902f32d2ac8405606e10dde52c6f82e9257ca06",
	"00008_key_vault.sql":                 "d73b58d21409745ec9b518d8b65f9bb5167c63df472457e1086ddeb26b972cbc",
	"00009_kv_version_chain.sql":          "1859bd4fae99bdf9f0b6f0a40069fec385def960628d1116a82e17bae4d475ff",
	"00010_ssh_key_rotation.sql":          "3dc9ad98a4a9ec1abc616e97d7f113f9c6a60363f0d8303c00cdd68600131e93",
	"00011_alerts_dashboard_sso.sql":      "3a906e1d0061e34aec9f49f2928d1e5e5ddce5f1e02669506782a9e8c22499fc",
	"00012_backup_sender.sql":             "5a6567ed9aae7c81916952532b3a4b26cc127b5531fc6c4b55cadc1257d9eccb",
	"00013_acme.sql":                      "2c2a5873fbe77b6c8759ba32910d2e4c3447bbd17a0a9e00c267d2c580580986",
	"00014_discovery.sql":                 "02ad411faabb3607d23093efcade34a7c21d07ad7e886e81bbaed83a1387331b",
	"00015_ldap.sql":                      "f5afd408fca17918a6a3da4299325419a5f3d6da9c0a11a10f16568df29d1228",
	"00016_web_server_standard.sql":       "9f7e32c7ec0b2ada3c645acca10506369bd87e5072eeac903fbc7350c4508492",
}

func TestReleasedMigrationsAreFrozen(t *testing.T) {
	for name, want := range frozen {
		data, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "frozen migration %s is missing", name)
		sum := sha256.Sum256(data)
		require.Equal(t, want, hex.EncodeToString(sum[:]),
			"migration %s changed: a released migration is never edited; add a new numbered migration (prod-readiness OPS-5, RA-04)", name)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	for _, e := range entries {
		if _, ok := frozen[e.Name()]; !ok && strings.HasSuffix(e.Name(), ".sql") {
			t.Logf("%s is not frozen yet (a new migration)", e.Name())
		}
	}
}
