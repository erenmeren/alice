package store

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RequireTLSVerification refuses a database URL that would not verify the server's certificate.
// Only a database on this computer may skip TLS. The URL is never echoed (it holds the password);
// envName is the environment variable that held it and is named in the messages.
func RequireTLSVerification(url, envName string) error {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return errors.New("the database URL is not valid; check " + envName)
	}
	verified := func(host string, conf *tls.Config) bool {
		return conf != nil && !conf.InsecureSkipVerify || loopback(host)
	}
	ok := verified(cfg.Host, cfg.TLSConfig)
	for _, f := range cfg.Fallbacks {
		ok = ok && verified(f.Host, f.TLSConfig)
	}
	if !ok {
		return errors.New("the database connection must verify the server certificate: add sslmode=verify-full to " + envName +
			" (only a database on this computer may skip TLS)")
	}
	return nil
}

func loopback(host string) bool {
	if host == "localhost" || strings.HasPrefix(host, "/") { // a unix socket is local too
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
