// Package apispec embeds the OpenAPI document, the source of truth for the HTTP API.
package apispec

import _ "embed"

// YAML is the OpenAPI 3.1 document.
//
//go:embed openapi.yaml
var YAML []byte
