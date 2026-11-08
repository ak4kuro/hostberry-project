package auth

import "strings"

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// ValidRoles roles permitidos en la aplicación.
var ValidRoles = map[string]struct{}{
	RoleAdmin:    {},
	RoleOperator: {},
}

// NormalizeRole devuelve el rol en minúsculas si es válido.
func NormalizeRole(role string) (string, bool) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		// Un rol vacío NO debe ascender a admin: devolver inválido.
		return "", false
	}
	_, ok := ValidRoles[role]
	return role, ok
}

// IsAdmin indica si el rol tiene permisos de administrador.
func IsAdmin(role string) bool {
	r, ok := NormalizeRole(role)
	return ok && r == RoleAdmin
}

// IsOperator indica si el rol es operator (solo lectura/operación limitada).
func IsOperator(role string) bool {
	r, ok := NormalizeRole(role)
	return ok && r == RoleOperator
}
