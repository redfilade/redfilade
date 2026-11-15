package sandbox

import (
	"strings"
	"testing"
)

func has(args []string, pair ...string) bool {
	s := "\x00" + strings.Join(args, "\x00") + "\x00"
	return strings.Contains(s, "\x00"+strings.Join(pair, "\x00")+"\x00")
}

func TestArgsAreHardened(t *testing.T) {
	a, err := Args(Spec{Name: "rf-1", Image: "redfilade/selftest:secure", WorldDir: "/tmp/run/world", Env: map[string]string{"A": "b"}, Tier: TierDocker})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]string{
		{"--network", "none"}, {"--read-only"}, {"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"}, {"--user", "65532:65532"},
		{"--pids-limit", "128"}, {"--memory", "256m"}, {"--ipc", "none"}, {"--pull", "never"},
		{"--mount", "type=bind,src=/tmp/run/world,dst=/world"}, {"--env", "A=b"},
		{"--", "redfilade/selftest:secure"},
	} {
		if !has(a, p...) {
			t.Errorf("missing %v in %v", p, a)
		}
	}
	for _, arg := range a {
		for _, bad := range []string{"--privileged", "--pid", "--userns", "--uts", "--device", "-v", "--volume", "--cap-add"} {
			if arg == bad || strings.HasPrefix(arg, bad+"=") {
				t.Errorf("forbidden flag %q in %v", arg, a)
			}
		}
		for _, bad := range []string{"docker.sock", ".ssh", "HOME=", ".aws"} {
			if strings.Contains(arg, bad) {
				t.Errorf("forbidden %q in %v", bad, a)
			}
		}
	}
}

func TestGVisorUsesRunsc(t *testing.T) {
	a, _ := Args(Spec{Name: "rf-1", Image: "x/y:z", Tier: TierGVisor})
	if !has(a, "--runtime", "runsc") {
		t.Fatal("gVisor tier without --runtime runsc")
	}
}

func TestRejectsDangerousSpecs(t *testing.T) {
	for name, s := range map[string]Spec{
		"host network":   {Name: "n", Image: "x/y", Network: "host"},
		"bridge network": {Name: "n", Image: "x/y", Network: "bridge"},
		"share netns":    {Name: "n", Image: "x/y", Network: "container:other"},
		"image flag":     {Name: "n", Image: "--privileged"},
		"name flag":      {Name: "-v", Image: "x/y"},
		"mount inject":   {Name: "n", Image: "x/y", WorldDir: "/tmp/w,dst=/etc"},
		"pull always":    {Name: "n", Image: "x/y", Pull: "always"},
	} {
		if _, err := Args(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestImageGoesAfterDoubleDash(t *testing.T) {
	a, _ := Args(Spec{Name: "n", Image: "x/y", Cmd: []string{"--privileged"}})
	i := 0
	for j, v := range a {
		if v == "--" {
			i = j
		}
	}
	if a[i+1] != "x/y" || a[i+2] != "--privileged" {
		t.Fatalf("cmd must follow the image after --: %v", a)
	}
}
