//go:build windows

package license

// These flags do not exist on Windows (0). The file time record is product-only
// and not supported on Windows; the vendor tools only need this package to link.
const (
	oNoFollow = 0
	oNonBlock = 0
)
