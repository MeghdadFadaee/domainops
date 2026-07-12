package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func encodeTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func encodeOptionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return encodeTime(*t)
}

func decodeTime(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode time %q: %w", raw, err)
	}
	return t, nil
}

func decodeOptionalTime(raw sql.NullString) (*time.Time, error) {
	if !raw.Valid {
		return nil, nil
	}
	t, err := decodeTime(raw.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func encodeJSON(value any) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeJSON(raw string, target any) error {
	if raw == "" {
		raw = "null"
	}
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

func rawOrNil(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

func copyRaw(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	return append([]byte(nil), raw...)
}
