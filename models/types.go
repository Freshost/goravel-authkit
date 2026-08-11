package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONMap is a map serialized to a Postgres jsonb column (used by AuditLog.Metadata).
type JSONMap map[string]any

func (m JSONMap) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Return a string (not []byte) so the pgx driver binds it as text → jsonb,
	// not bytea (which Postgres rejects with 22P02).
	return string(b), nil
}

// StringSlice stores a string list as JSON. API-token scopes use this instead
// of a delimiter-separated string so scope names remain exact and reversible.
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *StringSlice) Scan(src any) error {
	if src == nil {
		*s = StringSlice{}
		return nil
	}
	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("unsupported type %T for StringSlice", src)
	}
	return json.Unmarshal(b, s)
}

func (m *JSONMap) Scan(src any) error {
	if src == nil {
		*m = nil
		return nil
	}

	var b []byte
	switch v := src.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return fmt.Errorf("unsupported type %T for JSONMap", src)
	}

	return json.Unmarshal(b, m)
}
