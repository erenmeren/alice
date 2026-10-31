// Package winrs is Alice's WinRM transport for a Windows server target (R71, design §4.2 W7): a WinRS client
// that runs one program in one shell per call. It speaks only the six actions of the cmd shell resource URI
// (Create, Command, Send, Receive, Signal terminate, Delete), only over TLS 1.2 or later to a listener whose
// identity the caller pins through the TLS configuration, and authenticates only with NTLMv2 inside the
// Negotiate or NTLM HTTP scheme. Basic, Kerberos, CredSSP, client certificates, plain HTTP, redirects and
// proxies have no code path. The codec (wsman.go) also holds the server half the test emulator uses.
package winrs
