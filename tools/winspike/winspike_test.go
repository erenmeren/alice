//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// These run natively on the runner (go test ./tools/winspike/), to learn whether W1-W4's helper tests can use the
// real stores and http.sys from go test.

func TestMachineStoreOpens(t *testing.T) {
	h, err := openStore("My", true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(h)
	n := 0
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(h, prev)
		if err != nil {
			break
		}
		prev = ctx
		n++
	}
	t.Logf("LocalMachine\\My holds %d certificates", n)
}

func TestHTTPEnumerate(t *testing.T) {
	if err := httpInit(); err != nil {
		t.Fatal(err)
	}
	defer httpTerm()
	for _, id := range []uint32{configSSLCertInfo, configSslSniCertInfo, configSslCcsCertInfo} {
		list, err := enumerate(id)
		if err != nil {
			t.Fatalf("config %d: %v", id, err)
		}
		t.Logf("config %d: %d records", id, len(list))
	}
}

func TestGoPFXImportsInMemory(t *testing.T) {
	leaf := issue("test.spike", []string{"test.spike"}, false, false, nil)
	pfx, err := buildPFX(leaf.der, leaf.pkcs8(), "pw-123", true)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := windows.UTF16PtrFromString("pw-123")
	blob := windows.CryptDataBlob{Size: uint32(len(pfx)), Data: &pfx[0]}
	store, err := windows.PFXImportCertStore(&blob, pw, windows.PKCS12_NO_PERSIST_KEY)
	if err != nil {
		t.Fatalf("PFXImportCertStore: %v", err)
	}
	closeStore(store)
}
