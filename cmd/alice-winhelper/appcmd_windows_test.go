//go:build windows

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppcmdEnvKeepsOnlyTheAllowList(t *testing.T) {
	in := []string{
		"=C:=C:\\Users\\alice",
		"PATH=C:\\Windows\\system32;C:\\evil",
		"PATHEXT=.COM;.EXE;.BAT",
		"PSModulePath=C:\\modules",
		"SSH_ORIGINAL_COMMAND=iis-dump",
		"SSH_CONNECTION=10.0.0.1 50000 10.0.0.2 22",
		"SystemRoot=C:\\Windows",
		"windir=C:\\Windows",
		"TEMP=C:\\Temp",
		"ProgramFiles(x86)=C:\\Program Files (x86)",
		"COMPUTERNAME=WIN-ALICE",
		"temp=C:\\Second", // a second spelling of TEMP: the first wins
		"OS=Windows_NT",
		"OSX=not-allowed",
		"novalue",
	}
	assert.Equal(t, []string{"SystemRoot=C:\\Windows", "windir=C:\\Windows", "TEMP=C:\\Temp",
		"ProgramFiles(x86)=C:\\Program Files (x86)", "COMPUTERNAME=WIN-ALICE", "OS=Windows_NT"},
		appcmdEnv(in, "D:\\System"))

	// SystemRoot spelt in another case counts; when it is absent the system's is added.
	assert.Equal(t, []string{"SYSTEMROOT=C:\\Windows"}, appcmdEnv([]string{"SYSTEMROOT=C:\\Windows", "PATH=x"}, "D:\\System"))
	assert.Equal(t, []string{"USERNAME=alice", "SystemRoot=D:\\System"}, appcmdEnv([]string{"USERNAME=alice"}, "D:\\System"))
}
