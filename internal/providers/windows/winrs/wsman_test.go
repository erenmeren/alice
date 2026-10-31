package winrs

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	shellID = "11111111-2222-3333-4444-555555555555"
	cmdID   = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	program = `C:\Program Files\Alice\alice-helper.exe`
)

func hdr() Header {
	return Header{To: "https://127.0.0.1:5986/wsman", MessageID: "uuid:" + uuid.NewString(), OperationTimeout: 20 * time.Second}
}

func TestRequestsRoundTrip(t *testing.T) {
	env := map[string]string{"SSH_ORIGINAL_COMMAND": "version"}
	b, err := CreateShellRequest(hdr(), env, 90*time.Second)
	require.NoError(t, err)
	r, err := ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, ActionCreate, r.Action)
	assert.Equal(t, env, r.Env)
	assert.Empty(t, r.ShellID)
	assert.True(t, strings.HasPrefix(r.MessageID, "uuid:"))

	b, err = CreateShellRequest(hdr(), nil, time.Minute)
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Empty(t, r.Env)

	b, err = CommandRequest(hdr(), shellID, program, []string{"ssh"})
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, Request{Action: ActionCommand, MessageID: r.MessageID, ShellID: shellID, Program: program, Args: []string{"ssh"}}, r)

	stream := bytes.Repeat([]byte{0, 1, 2, 0xff}, 1000)
	for _, end := range []bool{false, true} {
		b, err = SendRequest(hdr(), shellID, cmdID, stream, end)
		require.NoError(t, err)
		r, err = ParseRequest(b)
		require.NoError(t, err)
		assert.Equal(t, ActionSend, r.Action)
		assert.Equal(t, shellID, r.ShellID)
		assert.Equal(t, cmdID, r.CommandID)
		assert.Equal(t, stream, r.Stream)
		assert.Equal(t, end, r.End)
	}
	b, err = SendRequest(hdr(), shellID, cmdID, nil, true)
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Empty(t, r.Stream)
	assert.True(t, r.End)

	b, err = ReceiveRequest(hdr(), shellID, cmdID)
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, ActionReceive, r.Action)
	assert.Equal(t, cmdID, r.CommandID)

	b, err = SignalRequest(hdr(), shellID, cmdID, SignalTerminate)
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, ActionSignal, r.Action)
	assert.Equal(t, cmdID, r.CommandID)
	assert.Equal(t, SignalTerminate, r.Signal)

	b, err = DeleteRequest(hdr(), shellID)
	require.NoError(t, err)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, ActionDelete, r.Action)
	assert.Equal(t, shellID, r.ShellID)
}

// The test's own reading of the envelope, independent of the package's parser.
type testEnvelope struct {
	Header struct {
		MaxEnvelopeSize struct {
			MustUnderstand string `xml:"http://www.w3.org/2003/05/soap-envelope mustUnderstand,attr"`
			Value          string `xml:",chardata"`
		} `xml:"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd MaxEnvelopeSize"`
		OperationTimeout string `xml:"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd OperationTimeout"`
		Options          []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd OptionSet>Option"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
	Body struct {
		Shell struct {
			IdleTimeOut string `xml:"IdleTimeOut"`
		} `xml:"http://schemas.microsoft.com/wbem/wsman/1/windows/shell Shell"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
}

func readEnvelope(t *testing.T, b []byte) testEnvelope {
	t.Helper()
	var e testEnvelope
	require.NoError(t, xml.Unmarshal(b, &e))
	return e
}

func options(e testEnvelope) map[string]string {
	m := map[string]string{}
	for _, o := range e.Header.Options {
		m[o.Name] = o.Value
	}
	return m
}

func TestRequestsCarryTheFixedOptions(t *testing.T) {
	b, err := CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": "version"}, 90*time.Second)
	require.NoError(t, err)
	e := readEnvelope(t, b)
	assert.Equal(t, map[string]string{"WINRS_NOPROFILE": "TRUE", "WINRS_CODEPAGE": "65001"}, options(e))
	assert.Equal(t, "153600", e.Header.MaxEnvelopeSize.Value)
	assert.Equal(t, "true", e.Header.MaxEnvelopeSize.MustUnderstand)
	assert.Equal(t, "PT20S", e.Header.OperationTimeout)
	assert.Equal(t, "PT90S", e.Body.Shell.IdleTimeOut)

	b, err = CommandRequest(hdr(), shellID, program, []string{"ssh"})
	require.NoError(t, err)
	e = readEnvelope(t, b)
	assert.Equal(t, map[string]string{"WINRS_CONSOLEMODE_STDIN": "FALSE", "WINRS_SKIP_CMD_SHELL": "TRUE"}, options(e))
	assert.Contains(t, string(b), `<rsp:Command>"C:\Program Files\Alice\alice-helper.exe"</rsp:Command>`)

	// A sub-second operation timeout is rounded up; none at all leaves the header out.
	h := hdr()
	h.OperationTimeout = 1500 * time.Millisecond
	b, err = ReceiveRequest(h, shellID, cmdID)
	require.NoError(t, err)
	assert.Equal(t, "PT2S", readEnvelope(t, b).Header.OperationTimeout)
	h.OperationTimeout = 0
	b, err = DeleteRequest(h, shellID)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "OperationTimeout")
}

// Element text escapes only '&', '<' and '>': Windows does not decode &#34; in the Command element (runner run 5).
// The server half reads both forms.
func TestRequestsWriteQuotesRaw(t *testing.T) {
	b, err := CommandRequest(hdr(), shellID, `C:\a&b\<x>.exe`, []string{"a&b", "'q'"})
	require.NoError(t, err)
	assert.Contains(t, string(b), `<rsp:Command>"C:\a&amp;b\&lt;x&gt;.exe"</rsp:Command>`)
	assert.Contains(t, string(b), `<rsp:Arguments>a&amp;b</rsp:Arguments><rsp:Arguments>'q'</rsp:Arguments>`)
	assert.NotContains(t, string(b), "&#34;")
	assert.NotContains(t, string(b), "&#39;")
	r, err := ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, `C:\a&b\<x>.exe`, r.Program)
	assert.Equal(t, []string{"a&b", "'q'"}, r.Args)

	b, err = CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": `a&b<c>'e'`}, time.Minute)
	require.NoError(t, err)
	assert.Contains(t, string(b), `>a&amp;b&lt;c&gt;'e'</rsp:Variable>`)
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, `a&b<c>'e'`, r.Env["SSH_ORIGINAL_COMMAND"])

	// The escaped quote form still parses.
	b, err = CommandRequest(hdr(), shellID, program, []string{"ssh"})
	require.NoError(t, err)
	b = bytes.ReplaceAll(b, []byte(`"C:`), []byte(`&#34;C:`))
	b = bytes.ReplaceAll(b, []byte(`.exe"`), []byte(`.exe&#34;`))
	r, err = ParseRequest(b)
	require.NoError(t, err)
	assert.Equal(t, program, r.Program)
}

func TestRequestsRefuseBadInput(t *testing.T) {
	ok := map[string]string{"SSH_ORIGINAL_COMMAND": "version"}
	tests := map[string]func() ([]byte, error){
		"two variables": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{"A": "1", "B": "2"}, time.Minute)
		},
		"lower-case name": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{"path": "x"}, time.Minute)
		},
		"long name": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{strings.Repeat("A", 33): "x"}, time.Minute)
		},
		"control byte": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": "a\nb"}, time.Minute)
		},
		"non-ASCII byte": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": "\xc3\xa9"}, time.Minute)
		},
		"long value": func() ([]byte, error) {
			return CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": strings.Repeat("a", 4097)}, time.Minute)
		},
		"no idle time": func() ([]byte, error) { return CreateShellRequest(hdr(), ok, 0) },
		"http address": func() ([]byte, error) {
			h := hdr()
			h.To = "http://h:5985/wsman"
			return CreateShellRequest(h, ok, time.Minute)
		},
		"address with a <": func() ([]byte, error) {
			h := hdr()
			h.To = "https://h<:5986/wsman"
			return CreateShellRequest(h, ok, time.Minute)
		},
		"bad message id": func() ([]byte, error) {
			h := hdr()
			h.MessageID = "urn:x"
			return CreateShellRequest(h, ok, time.Minute)
		},
		"upper message id": func() ([]byte, error) {
			h := hdr()
			h.MessageID = "uuid:" + cmdID
			return CreateShellRequest(h, ok, time.Minute)
		},
		"negative timeout":  func() ([]byte, error) { h := hdr(); h.OperationTimeout = -1; return DeleteRequest(h, shellID) },
		"lower shell id":    func() ([]byte, error) { return DeleteRequest(hdr(), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") },
		"empty shell id":    func() ([]byte, error) { return DeleteRequest(hdr(), "") },
		"bad command id":    func() ([]byte, error) { return ReceiveRequest(hdr(), shellID, "x") },
		"bad send shell":    func() ([]byte, error) { return SendRequest(hdr(), "x", cmdID, nil, true) },
		"bad signal id":     func() ([]byte, error) { return SignalRequest(hdr(), shellID, "x", SignalTerminate) },
		"bad signal shell":  func() ([]byte, error) { return SignalRequest(hdr(), "x", cmdID, SignalTerminate) },
		"other signal":      func() ([]byte, error) { return SignalRequest(hdr(), shellID, cmdID, "ctrl_c") },
		"bad receive shell": func() ([]byte, error) { return ReceiveRequest(hdr(), "x", cmdID) },
		"chunk too large": func() ([]byte, error) {
			return SendRequest(hdr(), shellID, cmdID, make([]byte, MaxSendChunk+1), true)
		},
		"bad command shell": func() ([]byte, error) { return CommandRequest(hdr(), "x", program, []string{"ssh"}) },
		"empty program":     func() ([]byte, error) { return CommandRequest(hdr(), shellID, "", nil) },
		"quoted program":    func() ([]byte, error) { return CommandRequest(hdr(), shellID, `"a"`, nil) },
		"empty argument":    func() ([]byte, error) { return CommandRequest(hdr(), shellID, program, []string{""}) },
		"argument with space": func() ([]byte, error) {
			return CommandRequest(hdr(), shellID, program, []string{"a b"})
		},
		"too many arguments": func() ([]byte, error) {
			return CommandRequest(hdr(), shellID, program, make([]string, 17))
		},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := f()
			require.Error(t, err)
			assert.Nil(t, b)
		})
	}
}

func received(inner string) []byte {
	return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header/><s:Body><rsp:ReceiveResponse>` + inner + `</rsp:ReceiveResponse></s:Body></s:Envelope>`)
}

func stream(name, id, data string) string {
	return `<rsp:Stream Name="` + name + `" CommandId="` + id + `">` + base64.StdEncoding.EncodeToString([]byte(data)) + `</rsp:Stream>`
}

func state(id, st, exit string) string {
	return `<rsp:CommandState CommandId="` + id + `" State="` + st + `">` + exit + `</rsp:CommandState>`
}

func TestParseReceived(t *testing.T) {
	running := "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"
	r, err := ParseReceived(received(stream("stdout", cmdID, "ab")+stream("stderr", cmdID, "err")+stream("stdout", cmdID, "cd")+state(cmdID, running, "")), cmdID)
	require.NoError(t, err)
	assert.Equal(t, Received{Stdout: []byte("abcd"), Stderr: []byte("err")}, r)

	r, err = ParseReceived(received(`<rsp:Stream Name="stdout" CommandId="`+cmdID+`" End="true"></rsp:Stream>`+state(cmdID, StateDone, "<rsp:ExitCode>3</rsp:ExitCode>")), cmdID)
	require.NoError(t, err)
	assert.Equal(t, Received{Done: true, ExitCode: 3}, r)

	r, err = ParseReceived(received(state(cmdID, StateDone, "<rsp:ExitCode>-1073741510</rsp:ExitCode>")), cmdID)
	require.NoError(t, err)
	assert.Equal(t, -1073741510, r.ExitCode)

	bad := map[string][]byte{
		"done without exit code": received(state(cmdID, StateDone, "")),
		"stream of another id":   received(stream("stdout", shellID, "x")),
		"state of another id":    received(state(shellID, running, "")),
		"unknown stream":         received(stream("stdin", cmdID, "x")),
		"invalid base64":         received(`<rsp:Stream Name="stdout" CommandId="` + cmdID + `">!!</rsp:Stream>`),
		"exit code over int32":   received(state(cmdID, StateDone, "<rsp:ExitCode>3221225786</rsp:ExitCode>")),
		"exit code not a number": received(state(cmdID, StateDone, "<rsp:ExitCode>x</rsp:ExitCode>")),
		"unknown element":        received(`<rsp:Other/>`),
		"two command states":     received(state(cmdID, running, "") + state(cmdID, running, "")),
		"over the body bound":    received(stream("stdout", cmdID, strings.Repeat("a", MaxResponseBody))),
		"not a receive response": ShellCreatedResponse("uuid:x", shellID),
		"not xml":                []byte("<"),
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := ParseReceived(b, cmdID)
			assert.ErrorIs(t, err, ErrProtocol)
		})
	}
}

func fault(detail string) []byte {
	return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">secret server text</s:Text></s:Reason>` + detail + `</s:Fault></s:Body></s:Envelope>`)
}

func TestParseFault(t *testing.T) {
	f, ok := ParseFault(fault(`<s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="2150858770" Machine="h"><f:Message>secret server text</f:Message></f:WSManFault></s:Detail>`))
	require.True(t, ok)
	assert.Equal(t, uint32(2150858770), f.Code)
	assert.NotContains(t, f.Error(), "secret")
	assert.Contains(t, f.Error(), "2150858770")

	f, ok = ParseFault(fault(`<s:Detail><f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" Code="x"/></s:Detail>`))
	require.True(t, ok)
	assert.Equal(t, &FaultError{}, f)

	f, ok = ParseFault(fault(""))
	require.True(t, ok)
	assert.Equal(t, &FaultError{}, f)

	f, ok = ParseFault(FaultResponse("uuid:x", 5))
	require.True(t, ok)
	assert.Equal(t, uint32(5), f.Code)

	for _, b := range [][]byte{[]byte("<"), received(""), []byte("not xml at all")} {
		_, ok = ParseFault(b)
		assert.False(t, ok)
	}
}

func TestParseRejectsHostileXML(t *testing.T) {
	deep := strings.Repeat("<a>", 33) + strings.Repeat("</a>", 33)
	env := func(body string) []byte {
		return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/><s:Body>` + body + `</s:Body></s:Envelope>`)
	}
	tests := map[string][]byte{
		"doctype":         []byte(`<!DOCTYPE s [<!ENTITY x "y">]><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`),
		"entity":          env(`&xxe;`),
		"deep nesting":    env(deep),
		"two bodies":      []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/><s:Body/></s:Envelope>`),
		"two headers":     []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/><s:Header/><s:Body/></s:Envelope>`),
		"no body":         []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/></s:Envelope>`),
		"other child":     []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Other/><s:Body/></s:Envelope>`),
		"wrong root":      []byte(`<Envelope><Body/></Envelope>`),
		"two roots":       []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope><x/>`),
		"text at the top": []byte(`x<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`),
		"processing inst": []byte(`<?php x?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`),
		"unclosed":        []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/>`),
		"empty":           nil,
		"too large":       env(strings.Repeat(" ", MaxResponseBody)),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseShellCreated(b)
			assert.ErrorIs(t, err, ErrProtocol)
			_, err = ParseRequest(b)
			assert.ErrorIs(t, err, ErrProtocol)
		})
	}
	// A comment and the XML declaration are harmless.
	b := append([]byte(`<?xml version="1.0" encoding="utf-8"?><!-- c -->`), ShellCreatedResponse("uuid:x", shellID)...)
	id, err := ParseShellCreated(b)
	require.NoError(t, err)
	assert.Equal(t, shellID, id)
}

func TestServerResponsesParse(t *testing.T) {
	id, err := ParseShellCreated(ShellCreatedResponse("uuid:x", shellID))
	require.NoError(t, err)
	assert.Equal(t, shellID, id)

	id, err = ParseCommandStarted(CommandStartedResponse("uuid:x", cmdID))
	require.NoError(t, err)
	assert.Equal(t, cmdID, id)

	r, err := ParseReceived(ReceivedResponse("uuid:x", cmdID, []byte("out"), false, 0), cmdID)
	require.NoError(t, err)
	assert.Equal(t, Received{Stdout: []byte("out")}, r)
	r, err = ParseReceived(ReceivedResponse("uuid:x", cmdID, nil, true, 4), cmdID)
	require.NoError(t, err)
	assert.Equal(t, Received{Done: true, ExitCode: 4}, r)
	r, err = ParseReceived(ReceivedStreamsResponse("uuid:x", cmdID, nil, []byte("not recognized"), true, 9009), cmdID)
	require.NoError(t, err)
	assert.Equal(t, Received{Stderr: []byte("not recognized"), Done: true, ExitCode: 9009}, r)

	for _, a := range []string{ActionSend, ActionSignal, ActionDelete} {
		b := EmptyResponse("uuid:<x>", a)
		_, ok := ParseFault(b)
		assert.False(t, ok, a)
		assert.Contains(t, string(b), a+"Response")
		assert.Contains(t, string(b), "uuid:&lt;x&gt;")
	}

	// The client half refuses the wrong response and a bad ID.
	_, err = ParseShellCreated(CommandStartedResponse("uuid:x", cmdID))
	assert.ErrorIs(t, err, ErrProtocol)
	_, err = ParseShellCreated(ShellCreatedResponse("uuid:x", "lower-case"))
	assert.ErrorIs(t, err, ErrProtocol)
	_, err = ParseCommandStarted(ShellCreatedResponse("uuid:x", shellID))
	assert.ErrorIs(t, err, ErrProtocol)
	_, err = ParseCommandStarted(CommandStartedResponse("uuid:x", "x"))
	assert.ErrorIs(t, err, ErrProtocol)
	_, err = ParseCommandStarted([]byte("<"))
	assert.ErrorIs(t, err, ErrProtocol)
}

func TestParseShellCreatedForms(t *testing.T) {
	wrap := func(body string) []byte {
		return []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body>` + body + `</s:Body></s:Envelope>`)
	}
	sel := func(id string) string {
		return `<x:ResourceCreated><a:ReferenceParameters><w:SelectorSet><w:Selector Name="ShellId">` + id + `</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated>`
	}
	shell := func(id string) string { return `<rsp:Shell><rsp:ShellId>` + id + `</rsp:ShellId></rsp:Shell>` }

	for _, body := range []string{sel(shellID), shell(shellID), sel(shellID) + shell(shellID)} {
		id, err := ParseShellCreated(wrap(body))
		require.NoError(t, err)
		assert.Equal(t, shellID, id)
	}
	other := strings.Replace(shellID, "1", "9", 1)
	for _, body := range []string{sel(shellID) + shell(other), "", `<rsp:Shell/>`} {
		_, err := ParseShellCreated(wrap(body))
		assert.ErrorIs(t, err, ErrProtocol)
	}
}

func TestParseRequestRefuses(t *testing.T) {
	good, err := SendRequest(hdr(), shellID, cmdID, []byte("x"), true)
	require.NoError(t, err)
	create, err := CreateShellRequest(hdr(), map[string]string{"SSH_ORIGINAL_COMMAND": "version"}, time.Minute)
	require.NoError(t, err)
	command, err := CommandRequest(hdr(), shellID, program, []string{"ssh"})
	require.NoError(t, err)
	signal, err := SignalRequest(hdr(), shellID, cmdID, SignalTerminate)
	require.NoError(t, err)
	receive, err := ReceiveRequest(hdr(), shellID, cmdID)
	require.NoError(t, err)
	del, err := DeleteRequest(hdr(), shellID)
	require.NoError(t, err)
	rep := func(b []byte, old, repl string) []byte {
		require.Contains(t, string(b), old)
		return bytes.Replace(b, []byte(old), []byte(repl), 1)
	}
	tests := map[string][]byte{
		"other resource":       rep(good, ResourceCmd, "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"),
		"other action":         rep(good, ActionSend, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"),
		"bad message id":       rep(good, "uuid:", "urn:"),
		"bad shell id":         rep(good, `"ShellId">`+shellID, `"ShellId">x`),
		"no shell id":          rep(del, `<w:SelectorSet><w:Selector Name="ShellId">`+shellID+`</w:Selector></w:SelectorSet>`, ""),
		"other selector":       rep(del, `Name="ShellId"`, `Name="Other"`),
		"bad send id":          rep(good, `CommandId="`+cmdID, `CommandId="x`),
		"stdout sent":          rep(good, `Name="stdin"`, `Name="stdout"`),
		"bad end":              rep(good, `End="true"`, `End="yes"`),
		"bad base64":           rep(good, `>eA==<`, `>!!<`),
		"send without stream":  rep(good, `<rsp:Stream`, `<rsp:Other`),
		"two variables":        rep(create, `</rsp:Environment>`, `<rsp:Variable Name="B">x</rsp:Variable></rsp:Environment>`),
		"bad variable":         rep(create, `Name="SSH_ORIGINAL_COMMAND"`, `Name="x"`),
		"shell on create":      rep(create, `<w:OptionSet>`, `<w:SelectorSet><w:Selector Name="ShellId">`+shellID+`</w:Selector></w:SelectorSet><w:OptionSet>`),
		"create without shell": rep(create, `<rsp:Shell>`, `<rsp:Other><rsp:Shell>`),
		"unquoted program":     rep(command, `"C:`, `C:`),
		"bad argument":         rep(command, `>ssh<`, `>a b<`),
		"no command line":      rep(command, `<rsp:CommandLine>`, `<rsp:Other><rsp:CommandLine>`),
		"other signal":         rep(signal, SignalTerminate, "ctrl_c"),
		"bad signal id":        rep(signal, `CommandId="`+cmdID, `CommandId="x`),
		"no signal":            rep(signal, `<rsp:Signal `, `<rsp:Other `),
		"bad receive id":       rep(receive, `CommandId="`+cmdID, `CommandId="x`),
		"no receive":           rep(receive, `<rsp:Receive>`, `<rsp:Other><rsp:Receive>`),
		"no header":            []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body/></s:Envelope>`),
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRequest(b)
			assert.ErrorIs(t, err, ErrProtocol)
		})
	}
}

func TestFaultErrorIsNotProtocol(t *testing.T) {
	var fe *FaultError
	err := error(&FaultError{Code: 2})
	assert.True(t, errors.As(err, &fe))
	assert.NotErrorIs(t, err, ErrProtocol)
}
