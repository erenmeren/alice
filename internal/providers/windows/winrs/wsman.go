package winrs

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The WS-Management subset Alice speaks (MS-WSMV, the cmd shell of WinRS) and its bounds.
const (
	ResourceCmd     = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	ActionCreate    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	ActionDelete    = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	ActionCommand   = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
	ActionSend      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
	ActionReceive   = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
	ActionSignal    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
	SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
	StateDone       = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
	ContentType     = "application/soap+xml;charset=UTF-8"
	MaxEnvelopeSize = 153600 // the MaxEnvelopeSize header Alice sends (F26 may lower it)
	MaxResponseBody = 256 << 10
	MaxSendChunk    = 96 << 10 // raw bytes of one Send (base64 ~128 KiB)
	MaxEnvVars      = 1
)

const (
	nsSOAP       = "http://www.w3.org/2003/05/soap-envelope"
	nsAddr       = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	nsWSMan      = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	nsShell      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	nsFault      = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
	nsTransfer   = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	anonymous    = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
	actionFault  = "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault"
	stateRunning = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"

	maxDepth    = 32
	maxArgs     = 16
	maxEnvValue = 4096 // the forced command line's own bound (Ruling 4)
)

// ErrProtocol is a malformed, unexpected or out-of-bounds WS-Management message.
var ErrProtocol = errors.New("winrs: malformed or unexpected WS-Management message")

// errBadInput is a request the codec refuses to build.
var errBadInput = errors.New("winrs: invalid request input")

// FaultError is a WS-Management fault. Only the WSManFault code is kept (0 when the fault has none): the
// fault's text comes from the server and is never kept, logged or shown. Action is the request it answered (one of
// the Action* constants), set by Client.Run; the parser leaves it empty.
type FaultError struct {
	Code   uint32
	Action string
}

func (e *FaultError) Error() string {
	return "winrs: WS-Management fault " + strconv.FormatUint(uint64(e.Code), 10)
}

// Header is what varies in a request's SOAP header. MessageID is "uuid:<lowercase uuid>"; an
// OperationTimeout of 0 leaves the header out.
type Header struct {
	To, MessageID    string
	OperationTimeout time.Duration
}

// Request is a parsed client request (the emulator's view, Task 3).
type Request struct {
	Action, MessageID, ShellID, CommandID, Program, Signal string
	Args                                                   []string
	Env                                                    map[string]string
	Stream                                                 []byte
	End                                                    bool
}

// Received is one Receive response: the streams of the command, and whether it is done.
type Received struct {
	Stdout, Stderr []byte
	Done           bool
	ExitCode       int
}

var (
	idRE      = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`)
	envNameRE = regexp.MustCompile(`^[A-Z_]{1,32}$`)
)

type option struct{ name, value string }

// printable reports whether s is non-empty printable ASCII (0x20-0x7E) without a double quote, and, when
// space is false, without a space.
func printable(s string, space bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || (c == ' ' && !space) {
			return false
		}
	}
	return true
}

func validEnv(env map[string]string) bool {
	if len(env) > MaxEnvVars {
		return false
	}
	for k, v := range env {
		if !envNameRE.MatchString(k) || len(v) > maxEnvValue || !printable(v, true) {
			return false
		}
	}
	return true
}

func validCommand(program string, args []string) bool {
	if !printable(program, true) || len(args) > maxArgs {
		return false
	}
	for _, a := range args {
		if !printable(a, false) {
			return false
		}
	}
	return true
}

func validMessageID(id string) bool {
	u, ok := strings.CutPrefix(id, "uuid:")
	if !ok {
		return false
	}
	p, err := uuid.Parse(u)
	return err == nil && p.String() == u // the canonical lowercase form only
}

// seconds is the xs:duration of d in whole seconds, rounded up.
func seconds(d time.Duration) string {
	return "PT" + strconv.FormatInt(int64((d+time.Second-1)/time.Second), 10) + "S"
}

// esc writes element text, escaping only '&', '<' and '>'. Quotes stay raw: Windows takes the Command element's text
// as it arrives, without turning &#34; back into a quote (runner run 5). The values are printable ASCII (validated).
func esc(b *bytes.Buffer, s string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteByte(c)
		}
	}
}

// escAttr writes an attribute value (quotes escaped too).
func escAttr(b *bytes.Buffer, s string) { _ = xml.EscapeText(b, []byte(s)) }

func envelope(h Header, action, shellID string, opts []option, body func(*bytes.Buffer)) ([]byte, error) {
	if !strings.HasPrefix(h.To, "https://") || !printable(h.To, false) || strings.ContainsAny(h.To, "<>&'") ||
		!validMessageID(h.MessageID) || h.OperationTimeout < 0 {
		return nil, errBadInput
	}
	var b bytes.Buffer
	b.WriteString(`<s:Envelope xmlns:s="` + nsSOAP + `" xmlns:a="` + nsAddr + `" xmlns:w="` + nsWSMan + `" xmlns:rsp="` + nsShell + `"><s:Header>`)
	b.WriteString(`<a:To>` + h.To + `</a:To>`)
	b.WriteString(`<w:ResourceURI s:mustUnderstand="true">` + ResourceCmd + `</w:ResourceURI>`)
	b.WriteString(`<a:ReplyTo><a:Address s:mustUnderstand="true">` + anonymous + `</a:Address></a:ReplyTo>`)
	b.WriteString(`<a:Action s:mustUnderstand="true">` + action + `</a:Action>`)
	b.WriteString(`<w:MaxEnvelopeSize s:mustUnderstand="true">` + strconv.Itoa(MaxEnvelopeSize) + `</w:MaxEnvelopeSize>`)
	b.WriteString(`<a:MessageID>` + h.MessageID + `</a:MessageID>`)
	if h.OperationTimeout > 0 {
		b.WriteString(`<w:OperationTimeout>` + seconds(h.OperationTimeout) + `</w:OperationTimeout>`)
	}
	if shellID != "" {
		b.WriteString(`<w:SelectorSet><w:Selector Name="ShellId">` + shellID + `</w:Selector></w:SelectorSet>`)
	}
	if len(opts) > 0 {
		b.WriteString(`<w:OptionSet>`)
		for _, o := range opts {
			b.WriteString(`<w:Option Name="` + o.name + `">` + o.value + `</w:Option>`)
		}
		b.WriteString(`</w:OptionSet>`)
	}
	b.WriteString(`</s:Header><s:Body>`)
	if body != nil {
		body(&b)
	}
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.Bytes(), nil
}

// CreateShellRequest creates a cmd shell with at most one environment variable and the idle time.
func CreateShellRequest(h Header, env map[string]string, idle time.Duration) ([]byte, error) {
	if !validEnv(env) || idle <= 0 {
		return nil, errBadInput
	}
	opts := []option{{"WINRS_NOPROFILE", "TRUE"}, {"WINRS_CODEPAGE", "65001"}}
	return envelope(h, ActionCreate, "", opts, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams>`)
		b.WriteString(`<rsp:IdleTimeOut>` + seconds(idle) + `</rsp:IdleTimeOut>`)
		if len(env) > 0 {
			b.WriteString(`<rsp:Environment>`)
			for k, v := range env {
				b.WriteString(`<rsp:Variable Name="` + k + `">`)
				esc(b, v)
				b.WriteString(`</rsp:Variable>`)
			}
			b.WriteString(`</rsp:Environment>`)
		}
		b.WriteString(`</rsp:Shell>`)
	})
}

// CommandRequest starts program (quoted on the wire) with args, without cmd.exe and with stdin as a pipe.
func CommandRequest(h Header, shellID, program string, args []string) ([]byte, error) {
	if !idRE.MatchString(shellID) || !validCommand(program, args) {
		return nil, errBadInput
	}
	opts := []option{{"WINRS_CONSOLEMODE_STDIN", "FALSE"}, {"WINRS_SKIP_CMD_SHELL", "TRUE"}}
	return envelope(h, ActionCommand, shellID, opts, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:CommandLine><rsp:Command>`)
		esc(b, `"`+program+`"`)
		b.WriteString(`</rsp:Command>`)
		for _, a := range args {
			b.WriteString(`<rsp:Arguments>`)
			esc(b, a)
			b.WriteString(`</rsp:Arguments>`)
		}
		b.WriteString(`</rsp:CommandLine>`)
	})
}

// SendRequest sends one chunk of stdin (at most MaxSendChunk bytes); end marks the last one.
func SendRequest(h Header, shellID, commandID string, chunk []byte, end bool) ([]byte, error) {
	if !idRE.MatchString(shellID) || !idRE.MatchString(commandID) || len(chunk) > MaxSendChunk {
		return nil, errBadInput
	}
	return envelope(h, ActionSend, shellID, nil, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:Send><rsp:Stream Name="stdin" CommandId="` + commandID + `"`)
		if end {
			b.WriteString(` End="true"`)
		}
		b.WriteString(`>` + base64.StdEncoding.EncodeToString(chunk) + `</rsp:Stream></rsp:Send>`)
	})
}

// ReceiveRequest asks for the command's stdout and stderr.
func ReceiveRequest(h Header, shellID, commandID string) ([]byte, error) {
	if !idRE.MatchString(shellID) || !idRE.MatchString(commandID) {
		return nil, errBadInput
	}
	return envelope(h, ActionReceive, shellID, nil, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:Receive><rsp:DesiredStream CommandId="` + commandID + `">stdout stderr</rsp:DesiredStream></rsp:Receive>`)
	})
}

// SignalRequest signals the command; code must be SignalTerminate, the only signal Alice sends.
func SignalRequest(h Header, shellID, commandID, code string) ([]byte, error) {
	if !idRE.MatchString(shellID) || !idRE.MatchString(commandID) || code != SignalTerminate {
		return nil, errBadInput
	}
	return envelope(h, ActionSignal, shellID, nil, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:Signal CommandId="` + commandID + `"><rsp:Code>` + code + `</rsp:Code></rsp:Signal>`)
	})
}

// DeleteRequest deletes the shell.
func DeleteRequest(h Header, shellID string) ([]byte, error) {
	if !idRE.MatchString(shellID) {
		return nil, errBadInput
	}
	return envelope(h, ActionDelete, shellID, nil, nil)
}

// node is one element of a parsed message.
type node struct {
	name  xml.Name
	attrs []xml.Attr
	kids  []*node
	text  []byte
}

func (n *node) all(space, local string) []*node {
	var out []*node
	for _, k := range n.kids {
		if k.name.Space == space && k.name.Local == local {
			out = append(out, k)
		}
	}
	return out
}

// one is the only child of that name (nil when there is none or more than one).
func (n *node) one(space, local string) *node {
	if n == nil {
		return nil
	}
	if l := n.all(space, local); len(l) == 1 {
		return l[0]
	}
	return nil
}

func (n *node) attr(local string) (string, bool) {
	for _, a := range n.attrs {
		if a.Name.Space == "" && a.Name.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

func (n *node) str() string {
	if n == nil {
		return ""
	}
	return strings.TrimSpace(string(n.text))
}

// parse reads one bounded document strictly: no DOCTYPE, no entity but XML's own, no processing
// instruction but the XML declaration, at most maxDepth elements deep, one root.
func parse(b []byte) (*node, error) {
	if len(b) == 0 || len(b) > MaxResponseBody {
		return nil, ErrProtocol
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var root *node
	var stack []*node
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrProtocol
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == maxDepth || (len(stack) == 0 && root != nil) {
				return nil, ErrProtocol
			}
			n := &node{name: t.Name, attrs: t.Copy().Attr}
			if len(stack) == 0 {
				root = n
			} else {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, ErrProtocol
				}
				continue
			}
			p := stack[len(stack)-1]
			p.text = append(p.text, t...)
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, ErrProtocol
			}
		case xml.Directive:
			return nil, ErrProtocol
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, ErrProtocol
	}
	return root, nil
}

// parseEnvelope returns the header (nil when absent) and the body of a SOAP 1.2 envelope that holds at
// most one Header, exactly one Body and nothing else.
func parseEnvelope(b []byte) (header, body *node, err error) {
	root, err := parse(b)
	if err != nil {
		return nil, nil, err
	}
	if root.name.Space != nsSOAP || root.name.Local != "Envelope" {
		return nil, nil, ErrProtocol
	}
	for _, k := range root.kids {
		switch {
		case k.name.Space == nsSOAP && k.name.Local == "Header" && header == nil:
			header = k
		case k.name.Space == nsSOAP && k.name.Local == "Body" && body == nil:
			body = k
		default:
			return nil, nil, ErrProtocol
		}
	}
	if body == nil {
		return nil, nil, ErrProtocol
	}
	return header, body, nil
}

// ParseShellCreated reads the shell ID of a Create response, from the ResourceCreated selector, the Shell
// element, or both (which must agree).
func ParseShellCreated(b []byte) (string, error) {
	_, body, err := parseEnvelope(b)
	if err != nil {
		return "", err
	}
	var ids []string
	if sel := body.one(nsTransfer, "ResourceCreated").one(nsAddr, "ReferenceParameters").one(nsWSMan, "SelectorSet"); sel != nil {
		for _, s := range sel.all(nsWSMan, "Selector") {
			if name, _ := s.attr("Name"); name == "ShellId" {
				ids = append(ids, s.str())
			}
		}
	}
	if id := body.one(nsShell, "Shell").one(nsShell, "ShellId"); id != nil {
		ids = append(ids, id.str())
	}
	if len(ids) == 0 {
		return "", ErrProtocol
	}
	for _, id := range ids {
		if id != ids[0] || !idRE.MatchString(id) {
			return "", ErrProtocol
		}
	}
	return ids[0], nil
}

// ParseCommandStarted reads the command ID of a Command response.
func ParseCommandStarted(b []byte) (string, error) {
	_, body, err := parseEnvelope(b)
	if err != nil {
		return "", err
	}
	id := body.one(nsShell, "CommandResponse").one(nsShell, "CommandId").str()
	if !idRE.MatchString(id) {
		return "", ErrProtocol
	}
	return id, nil
}

// ParseReceived reads one Receive response of commandID: its stdout and stderr chunks in order and, when the
// command is done, its exit code (a signed 32-bit value).
func ParseReceived(b []byte, commandID string) (Received, error) {
	_, body, err := parseEnvelope(b)
	if err != nil {
		return Received{}, err
	}
	resp := body.one(nsShell, "ReceiveResponse")
	if resp == nil {
		return Received{}, ErrProtocol
	}
	var r Received
	states := 0
	for _, k := range resp.kids {
		id, _ := k.attr("CommandId")
		if k.name.Space != nsShell || id != commandID {
			return Received{}, ErrProtocol
		}
		switch k.name.Local {
		case "Stream":
			data, err := base64.StdEncoding.DecodeString(k.str())
			if err != nil {
				return Received{}, ErrProtocol
			}
			switch name, _ := k.attr("Name"); name {
			case "stdout":
				r.Stdout = append(r.Stdout, data...)
			case "stderr":
				r.Stderr = append(r.Stderr, data...)
			default:
				return Received{}, ErrProtocol
			}
		case "CommandState":
			if states++; states > 1 {
				return Received{}, ErrProtocol
			}
			if st, _ := k.attr("State"); st == StateDone {
				code, err := strconv.ParseInt(k.one(nsShell, "ExitCode").str(), 10, 32)
				if err != nil {
					return Received{}, ErrProtocol
				}
				r.Done, r.ExitCode = true, int(code)
			}
		default:
			return Received{}, ErrProtocol
		}
	}
	return r, nil
}

// ParseFault reports whether b is a SOAP fault, and its WSManFault code (0 when absent or not a number).
func ParseFault(b []byte) (*FaultError, bool) {
	_, body, err := parseEnvelope(b)
	if err != nil {
		return nil, false
	}
	f := body.one(nsSOAP, "Fault")
	if f == nil {
		return nil, false
	}
	fe := &FaultError{}
	if wf := f.one(nsSOAP, "Detail").one(nsFault, "WSManFault"); wf != nil {
		c, _ := wf.attr("Code")
		if n, err := strconv.ParseUint(c, 10, 32); err == nil {
			fe.Code = uint32(n)
		}
	}
	return fe, true
}

// ParseRequest reads a client request of the subset (the emulator's half): the cmd resource URI, one of the
// six actions, and each action's fields under the same rules the builders apply.
func ParseRequest(b []byte) (Request, error) {
	header, body, err := parseEnvelope(b)
	if err != nil {
		return Request{}, err
	}
	if header.one(nsWSMan, "ResourceURI").str() != ResourceCmd {
		return Request{}, ErrProtocol
	}
	r := Request{Action: header.one(nsAddr, "Action").str(), MessageID: header.one(nsAddr, "MessageID").str()}
	if !validMessageID(r.MessageID) {
		return Request{}, ErrProtocol
	}
	if sel := header.one(nsWSMan, "SelectorSet"); sel != nil {
		s := sel.one(nsWSMan, "Selector")
		if name, _ := s.attr("Name"); s == nil || name != "ShellId" || !idRE.MatchString(s.str()) {
			return Request{}, ErrProtocol
		}
		r.ShellID = s.str()
	}
	if (r.Action == ActionCreate) != (r.ShellID == "") {
		return Request{}, ErrProtocol
	}
	ok := false
	switch r.Action {
	case ActionCreate:
		ok = parseCreate(body, &r)
	case ActionCommand:
		ok = parseCommand(body, &r)
	case ActionSend:
		ok = parseSend(body, &r)
	case ActionReceive:
		ds := body.one(nsShell, "Receive").one(nsShell, "DesiredStream")
		r.CommandID, _ = ds.attrOf("CommandId")
		ok = idRE.MatchString(r.CommandID)
	case ActionSignal:
		sig := body.one(nsShell, "Signal")
		r.CommandID, _ = sig.attrOf("CommandId")
		r.Signal = sig.one(nsShell, "Code").str()
		ok = idRE.MatchString(r.CommandID) && r.Signal == SignalTerminate
	case ActionDelete:
		ok = true
	}
	if !ok {
		return Request{}, ErrProtocol
	}
	return r, nil
}

// attrOf is attr on a node that may be nil.
func (n *node) attrOf(local string) (string, bool) {
	if n == nil {
		return "", false
	}
	return n.attr(local)
}

func parseCreate(body *node, r *Request) bool {
	shell := body.one(nsShell, "Shell")
	if shell == nil {
		return false
	}
	if e := shell.one(nsShell, "Environment"); e != nil {
		r.Env = map[string]string{}
		for _, v := range e.all(nsShell, "Variable") {
			name, _ := v.attr("Name")
			r.Env[name] = string(v.text)
		}
		if len(e.kids) != len(r.Env) {
			return false
		}
	}
	return validEnv(r.Env)
}

func parseCommand(body *node, r *Request) bool {
	cl := body.one(nsShell, "CommandLine")
	if cl == nil {
		return false
	}
	p := cl.one(nsShell, "Command").str()
	if len(p) < 2 || p[0] != '"' || p[len(p)-1] != '"' {
		return false
	}
	r.Program = p[1 : len(p)-1]
	for _, a := range cl.all(nsShell, "Arguments") {
		r.Args = append(r.Args, a.str())
	}
	return validCommand(r.Program, r.Args)
}

func parseSend(body *node, r *Request) bool {
	s := body.one(nsShell, "Send").one(nsShell, "Stream")
	if s == nil {
		return false
	}
	name, _ := s.attr("Name")
	r.CommandID, _ = s.attr("CommandId")
	end, hasEnd := s.attr("End")
	data, err := base64.StdEncoding.DecodeString(s.str())
	if name != "stdin" || !idRE.MatchString(r.CommandID) || (hasEnd && end != "true") || err != nil || len(data) > MaxSendChunk {
		return false
	}
	r.Stream, r.End = data, hasEnd
	return true
}

// response builds a server response envelope.
func response(action, relatesTo string, body func(*bytes.Buffer)) []byte {
	var b bytes.Buffer
	b.WriteString(`<s:Envelope xmlns:s="` + nsSOAP + `" xmlns:a="` + nsAddr + `" xmlns:w="` + nsWSMan + `" xmlns:x="` + nsTransfer + `" xmlns:rsp="` + nsShell + `"><s:Header>`)
	b.WriteString(`<a:Action>` + action + `</a:Action><a:MessageID>uuid:` + uuid.NewString() + `</a:MessageID>`)
	b.WriteString(`<a:To>` + anonymous + `</a:To><a:RelatesTo>`)
	esc(&b, relatesTo)
	b.WriteString(`</a:RelatesTo></s:Header><s:Body>`)
	if body != nil {
		body(&b)
	}
	b.WriteString(`</s:Body></s:Envelope>`)
	return b.Bytes()
}

// ShellCreatedResponse answers Create as Windows does: the ResourceCreated selector and the Shell element.
func ShellCreatedResponse(relatesTo, shellID string) []byte {
	return response(ActionCreate+"Response", relatesTo, func(b *bytes.Buffer) {
		b.WriteString(`<x:ResourceCreated><a:Address>` + anonymous + `</a:Address><a:ReferenceParameters><w:ResourceURI>` + ResourceCmd + `</w:ResourceURI><w:SelectorSet><w:Selector Name="ShellId">`)
		esc(b, shellID)
		b.WriteString(`</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell><rsp:ShellId>`)
		esc(b, shellID)
		b.WriteString(`</rsp:ShellId></rsp:Shell>`)
	})
}

// CommandStartedResponse answers Command.
func CommandStartedResponse(relatesTo, commandID string) []byte {
	return response(ActionCommand+"Response", relatesTo, func(b *bytes.Buffer) {
		b.WriteString(`<rsp:CommandResponse><rsp:CommandId>`)
		esc(b, commandID)
		b.WriteString(`</rsp:CommandId></rsp:CommandResponse>`)
	})
}

// ReceivedResponse answers Receive with one stdout chunk (none when empty) and the command's state.
func ReceivedResponse(relatesTo, commandID string, stdout []byte, done bool, exitCode int) []byte {
	return response(ActionReceive+"Response", relatesTo, func(b *bytes.Buffer) {
		var id bytes.Buffer
		escAttr(&id, commandID)
		b.WriteString(`<rsp:ReceiveResponse>`)
		if len(stdout) > 0 {
			b.WriteString(`<rsp:Stream Name="stdout" CommandId="` + id.String() + `">` + base64.StdEncoding.EncodeToString(stdout) + `</rsp:Stream>`)
		}
		st := stateRunning
		if done {
			st = StateDone
			b.WriteString(`<rsp:Stream Name="stdout" CommandId="` + id.String() + `" End="true"></rsp:Stream>`)
		}
		b.WriteString(`<rsp:CommandState CommandId="` + id.String() + `" State="` + st + `">`)
		if done {
			b.WriteString(`<rsp:ExitCode>` + strconv.Itoa(exitCode) + `</rsp:ExitCode>`)
		}
		b.WriteString(`</rsp:CommandState></rsp:ReceiveResponse>`)
	})
}

// EmptyResponse answers Send, Signal and Delete.
func EmptyResponse(relatesTo, action string) []byte {
	return response(action+"Response", relatesTo, nil)
}

// FaultResponse is a WS-Management fault with code (the emulator sends it with HTTP 500, as Windows does).
func FaultResponse(relatesTo string, code uint32) []byte {
	return response(actionFault, relatesTo, func(b *bytes.Buffer) {
		b.WriteString(`<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">fault</s:Text></s:Reason>`)
		b.WriteString(`<s:Detail><f:WSManFault xmlns:f="` + nsFault + `" Code="` + strconv.FormatUint(uint64(code), 10) + `" Machine="localhost"></f:WSManFault></s:Detail></s:Fault>`)
	})
}
