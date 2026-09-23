package collector

import (
	"path/filepath"
	"sort"
	"strings"
)

// suspiciousIdentity flags common OS-looking process names when they execute
// from locations where ordinary users can commonly place binaries. It is a
// triage signal, not proof of malware or code signing validation.
func suspiciousIdentity(name, executable string) bool {
	base := strings.ToLower(filepath.Base(name))
	switch base {
	case "systemupdate", "system-update", "isync", "softwareupdate", "systemd", "launchd", "securityd", "kernel_task":
	default:
		return false
	}
	path := filepath.Clean(executable)
	if !filepath.IsAbs(path) {
		return false // cannot make a path-based judgment without an absolute path
	}
	for _, root := range []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/lib", "/System/Library", "/System/Cryptexes/OS/System/Library", "/Applications",
	} {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return false
		}
	}
	return path != "" && path != "."
}

func processIdentityChanged(old, current procInfo) bool {
	return old.startTime != current.startTime || old.ppid != current.ppid ||
		old.name != current.name || old.executable != current.executable || old.user != current.user
}

func changedProcesses(previous, current map[int]procInfo) []procInfo {
	changed := make([]procInfo, 0)
	for pid, info := range current {
		old, existed := previous[pid]
		if !existed || processIdentityChanged(old, info) {
			changed = append(changed, info)
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].pid < changed[j].pid })
	return changed
}

func parentChildSignal(child procInfo, processes map[int]procInfo) (Severity, string, bool) {
	parent, ok := processes[child.ppid]
	if !ok {
		return "", "", false
	}
	parentName := filepath.Base(parent.name)
	childName := filepath.Base(child.name)
	suspicious, ok := suspiciousChildren[parentName]
	if !ok {
		return "", "", false
	}
	for _, name := range suspicious {
		if strings.HasPrefix(childName, name) {
			severity := SeverityHigh
			if childName == "sh" || childName == "bash" {
				severity = SeverityCritical
			}
			return severity, parentName, true
		}
	}
	return "", "", false
}
