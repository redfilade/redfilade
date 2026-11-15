// Command sql-injection is a Range target: a customer lookup tool.
//
//	vulnerable: the name is pasted into a SQL string, so quotes, OR and UNION
//	            change the query, and database errors are returned verbatim
//	secure:     the name is compared as a value and never becomes SQL; errors
//	            are generic
//
// The data lives in a small in-memory SQL engine (sql.go) so the image needs
// no database. Deliberately vulnerable in its vulnerable build. Run it only in
// a Redfilade cell.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/redfilade/redfilade/targets/internal/mcpserver"
)

var mode = "secure"

func main() {
	secret := os.Getenv("API_SECRET")
	if secret == "" {
		secret = "unset"
	}
	db := &database{tables: map[string]*table{
		"customers": {cols: []string{"id", "name", "email"}, rows: [][]any{
			{1.0, "Asha Rao", "asha@example.test"},
			{2.0, "Ben Ito", "ben@example.test"},
			{3.0, "Chen Wu", "chen@example.test"},
		}},
		"api_keys": {cols: []string{"service", "secret"}, rows: [][]any{
			{"billing", secret},
		}},
	}}
	mcpserver.Serve("redfilade-target-sql-injection", []mcpserver.Tool{{
		Name:        "find_customer",
		Description: "Look up a customer by exact name.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"name": map[string]any{"type": "string", "description": "customer name"},
		}, "required": []string{"name"}},
		Handle: func(args map[string]any) (string, bool) {
			name, _ := mcpserver.Str(args, "name")
			if mode == "vulnerable" {
				// The classic mistake: build SQL by string concatenation.
				q := "SELECT id, name, email FROM customers WHERE name = '" + name + "'"
				res, err := db.query(q)
				if err != nil {
					return "database error: " + err.Error() + "\nquery: " + q, true
				}
				return format(res), false
			}
			var rows [][]any
			for _, r := range db.tables["customers"].rows {
				if r[1] == name {
					rows = append(rows, r)
				}
			}
			return format(rows), false
		},
	}})
}

func format(rows [][]any) string {
	if len(rows) == 0 {
		return "no customer found"
	}
	var b strings.Builder
	for _, r := range rows {
		parts := make([]string, len(r))
		for i, v := range r {
			parts[i] = show(v)
		}
		fmt.Fprintln(&b, strings.Join(parts, " | "))
	}
	return strings.TrimRight(b.String(), "\n")
}
