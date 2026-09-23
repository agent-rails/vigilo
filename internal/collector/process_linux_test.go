//go:build linux

package collector

import (
	"os"
	"testing"
)

func TestReadProcInfoIncludesStableProcessStartIdentity(t *testing.T) {
	info, err := readProcInfo(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if info.startTime == "" || info.executable == "" || info.pid != os.Getpid() {
		t.Fatalf("process start/executable identity missing: %+v", info)
	}
}
