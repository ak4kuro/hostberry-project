package utils

import (
	"os/exec"
	"testing"
)

func TestValidateShellCommandAllowList_AllowedBasics(t *testing.T) {
	allowed := []string{"ip", "grep", "echo", "nmcli"}

	cases := []struct {
		name string
		cmd  string
		ok   bool
	}{
		{"simple_ip", "ip route", true},
		{"pipe", "ip route | grep foo", true},
		{"or", "ip route || grep foo", true},
		{"and", "ip route && grep foo", true},
		{"quoted_operator_is_literal", "ip route '&& rm -rf /'", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateShellCommandAllowList(tc.cmd, allowed)
			if tc.ok && err != nil {
				t.Fatalf("expected allow, got err=%v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected deny, got allow")
			}
		})
	}
}

func TestValidateShellCommandAllowList_Denies(t *testing.T) {
	allowed := []string{"ip", "grep", "echo"}

	cases := []struct {
		name string
		cmd  string
	}{
		{"not_allowed_base", "rm -rf /"},
		{"semicolon", "ip route; rm -rf /"},
		{"backticks", "ip route `id`"},
		{"unbalanced_single_quote", "ip route 'grep foo"},
		{"lone_ampersand_background", "ip route & rm -rf /"},
		{"lone_ampersand_no_space", "ip route&rm -rf /"},
		{"ampersand_redirect_both", "ip route &> /dev/null"},
		{"pipe_ampersand", "ip route |& grep foo"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateShellCommandAllowList(tc.cmd, allowed)
			if err == nil {
				t.Fatalf("expected deny, got allow")
			}
			if err != exec.ErrNotFound {
				// validateShellCommandAllowList actualmente usa exec.ErrNotFound como señal.
				t.Fatalf("expected exec.ErrNotFound, got %v", err)
			}
		})
	}
}

func TestValidateShellCommandAllowList_Redirections(t *testing.T) {
	allowed := []string{"echo", "systemctl"}

	cases := []struct {
		name string
		cmd  string
		ok   bool
	}{
		{"redirect_stdout_devnull", "echo ok > /dev/null", true},
		{"redirect_stderr_devnull", "echo ok 2> /dev/null", true},
		{"redirect_stderr_to_stdout", "echo ok 2>&1", true},
		{"redirect_append_forbidden", "echo ok >> /dev/null", false},
		{"redirect_in_forbidden", "echo ok < /etc/passwd", false},
		{"redirect_to_other_file_forbidden", "echo ok > /tmp/x", false},
		// Espaciado variable alrededor del 2>&1.
		{"stderr_to_stdout_no_space", "systemctl restart dnsmasq 2>&1", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateShellCommandAllowList(tc.cmd, allowed)
			if tc.ok && err != nil {
				t.Fatalf("expected allow, got err=%v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected deny, got allow")
			}
		})
	}
}
