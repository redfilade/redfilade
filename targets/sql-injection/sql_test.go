package main

import (
	"strings"
	"testing"
)

func testDB() *database {
	return &database{tables: map[string]*table{
		"customers": {cols: []string{"id", "name", "email"}, rows: [][]any{
			{1.0, "Asha Rao", "asha@example.test"}, {2.0, "Ben Ito", "ben@example.test"}}},
		"api_keys": {cols: []string{"service", "secret"}, rows: [][]any{{"billing", "SECRET-VALUE"}}},
	}}
}

func vulnerableQuery(name string) string {
	return "SELECT id, name, email FROM customers WHERE name = '" + name + "'"
}

func TestInjectionBehavesLikeSQL(t *testing.T) {
	db := testDB()
	cases := []struct {
		name     string
		rows     int
		contains string
		errPart  string
	}{
		{name: "Asha Rao", rows: 1, contains: "asha@"},
		{name: "nobody", rows: 0},
		{name: "x' OR '1'='1", rows: 2},
		{name: "x' OR 1=1--", rows: 2},
		{name: "x' UNION SELECT 0, service, secret FROM api_keys--", rows: 1, contains: "SECRET-VALUE"},
		{name: "x' UNION SELECT NULL--", errPart: "same number of result columns"},
		{name: "'", errPart: "unrecognized token"},
		{name: "x' AND nosuch = 1--", errPart: "no such column: nosuch"},
		{name: "x' UNION SELECT a, b, c FROM missing--", errPart: "no such table: missing"},
		{name: "x' garbage--", errPart: "near \"garbage\": syntax error"},
		{name: "x' garbage", errPart: "unrecognized token"},
		{name: "O''Brien", rows: 0},
		{name: "x' OR name LIKE 'B%", rows: 1, contains: "Ben Ito"},
	}
	for _, c := range cases {
		res, err := db.query(vulnerableQuery(c.name))
		if c.errPart != "" {
			if err == nil || !strings.Contains(err.Error(), c.errPart) {
				t.Errorf("%q: want error containing %q, got %v", c.name, c.errPart, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.name, err)
			continue
		}
		if len(res) != c.rows {
			t.Errorf("%q: %d rows, want %d", c.name, len(res), c.rows)
		}
		if c.contains != "" && !strings.Contains(format(res), c.contains) {
			t.Errorf("%q: output %q lacks %q", c.name, format(res), c.contains)
		}
	}
}
