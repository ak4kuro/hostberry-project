package auth

import "testing"

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		in    string
		ok    bool
		want  string
	}{
		{"admin", true, RoleAdmin},
		{"operator", true, RoleOperator},
		{"ADMIN", true, RoleAdmin},
		{"guest", false, "guest"},
		// Un rol vacío NO debe ascender a admin (endurecido en c9f1856).
		{"", false, ""},
	}
	for _, tc := range tests {
		got, ok := NormalizeRole(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("NormalizeRole(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsAdmin(t *testing.T) {
	if !IsAdmin("admin") {
		t.Fatal("admin should be admin")
	}
	if IsAdmin("operator") {
		t.Fatal("operator should not be admin")
	}
}
