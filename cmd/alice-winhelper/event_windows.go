//go:build windows

package main

// The Application log entries of iis-deploy and iis-restore (W2 Ruling 13): source "Alice Helper",
// type information, the text winhelper gives as the one insertion string (no key material, §15 Q10).
// Best effort: the journal is the record, so any failure is ignored.

import "golang.org/x/sys/windows"

const eventSource = "Alice Helper"

// maxEventText bounds an insertion string (ReportEvent takes at most 31,839 characters).
const maxEventText = 31839

// Event writes one Application event (winhelper.WriteHost).
func (host) Event(id uint32, text string) {
	if len(text) > maxEventText {
		text = text[:maxEventText]
	}
	src, err := windows.UTF16PtrFromString(eventSource)
	if err != nil {
		return
	}
	s, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return // a NUL in the text
	}
	h, err := windows.RegisterEventSource(nil, src)
	if err != nil {
		return
	}
	defer func() { _ = windows.DeregisterEventSource(h) }()
	_ = windows.ReportEvent(h, windows.EVENTLOG_INFORMATION_TYPE, 0, id, 0, 1, 0, &s, nil)
}
