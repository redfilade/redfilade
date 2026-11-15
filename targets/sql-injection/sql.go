package main

// A tiny, read-only SQL engine: enough SQL to show how injection works.
//
//	query  := select (UNION [ALL] select)* [";"]
//	select := SELECT cols [FROM table [WHERE expr]]
//	cols   := "*" | expr ("," expr)*
//	expr   := and (OR and)* ; and := not (AND not)* ; not := NOT not | cmp
//	cmp    := operand [("=" | "!=" | "<>" | "<" | ">" | LIKE) operand]
//	operand:= column | 'string' | number | NULL | "(" expr ")"
//
// "--" starts a comment. Error messages follow SQLite's wording.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type table struct {
	cols []string
	rows [][]any // values are nil, string, float64 or bool
}

type database struct{ tables map[string]*table }

type tok struct {
	kind string // "ident", "kw", "str", "num", "sym", "eof"
	text string
}

var keywords = map[string]bool{"SELECT": true, "FROM": true, "WHERE": true, "UNION": true, "ALL": true,
	"AND": true, "OR": true, "NOT": true, "LIKE": true, "NULL": true}

func lexSQL(q string) ([]tok, error) {
	var out []tok
	i := 0
	for i < len(q) {
		c := rune(q[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case strings.HasPrefix(q[i:], "--"):
			for i < len(q) && q[i] != '\n' {
				i++
			}
		case c == '\'':
			j := i + 1
			var b strings.Builder
			for {
				if j >= len(q) {
					return nil, fmt.Errorf("unrecognized token: \"%s\"", q[i:])
				}
				if q[j] == '\'' {
					if j+1 < len(q) && q[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(q[j])
				j++
			}
			out = append(out, tok{"str", b.String()})
			i = j + 1
		case unicode.IsDigit(c):
			j := i
			for j < len(q) && (unicode.IsDigit(rune(q[j])) || q[j] == '.') {
				j++
			}
			out = append(out, tok{"num", q[i:j]})
			i = j
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < len(q) && (unicode.IsLetter(rune(q[j])) || unicode.IsDigit(rune(q[j])) || q[j] == '_') {
				j++
			}
			w := q[i:j]
			if keywords[strings.ToUpper(w)] {
				out = append(out, tok{"kw", strings.ToUpper(w)})
			} else {
				out = append(out, tok{"ident", strings.ToLower(w)})
			}
			i = j
		default:
			for _, s := range []string{"!=", "<>", "=", "<", ">", ",", "(", ")", "*", ";"} {
				if strings.HasPrefix(q[i:], s) {
					out = append(out, tok{"sym", s})
					i += len(s)
					goto next
				}
			}
			return nil, fmt.Errorf("unrecognized token: \"%c\"", c)
		next:
		}
	}
	return append(out, tok{"eof", ""}), nil
}

type sqlParser struct {
	toks []tok
	pos  int
	db   *database
	refs []string // column names referenced by the current SELECT
}

func (p *sqlParser) peek() tok { return p.toks[p.pos] }
func (p *sqlParser) next() tok { t := p.toks[p.pos]; p.pos++; return t }
func (p *sqlParser) is(kind, text string) bool {
	t := p.peek()
	return t.kind == kind && t.text == text
}

func syntaxErr(t tok) error {
	if t.kind == "eof" {
		return fmt.Errorf("incomplete input")
	}
	return fmt.Errorf("near \"%s\": syntax error", t.text)
}

// row is evaluated against the current table's columns.
type evalRow struct {
	cols []string
	vals []any
}

type expr func(r evalRow) (any, error)

func (db *database) query(q string) ([][]any, error) {
	toks, err := lexSQL(q)
	if err != nil {
		return nil, err
	}
	p := &sqlParser{toks: toks, db: db}
	res, width, err := p.selectStmt()
	if err != nil {
		return nil, err
	}
	for p.is("kw", "UNION") {
		p.next()
		if p.is("kw", "ALL") {
			p.next()
		}
		more, w, err := p.selectStmt()
		if err != nil {
			return nil, err
		}
		if w != width {
			return nil, fmt.Errorf("SELECTs to the left and right of UNION do not have the same number of result columns")
		}
		res = append(res, more...)
	}
	if p.is("sym", ";") {
		p.next()
	}
	if p.peek().kind != "eof" {
		return nil, syntaxErr(p.peek())
	}
	return res, nil
}

// selectStmt returns the rows and the number of result columns.
func (p *sqlParser) selectStmt() ([][]any, int, error) {
	rows, width, err := p.selectInner()
	return rows, width, err
}

func (p *sqlParser) selectInner() ([][]any, int, error) {
	if !p.is("kw", "SELECT") {
		return nil, 0, syntaxErr(p.peek())
	}
	p.next()
	p.refs = nil
	star := false
	var cols []expr
	if p.is("sym", "*") {
		p.next()
		star = true
	} else {
		for {
			e, err := p.or()
			if err != nil {
				return nil, 0, err
			}
			cols = append(cols, e)
			if !p.is("sym", ",") {
				break
			}
			p.next()
		}
	}
	t := &table{rows: [][]any{{}}} // SELECT without FROM yields one row
	if p.is("kw", "FROM") {
		p.next()
		name := p.next()
		if name.kind != "ident" {
			return nil, 0, syntaxErr(name)
		}
		var ok bool
		if t, ok = p.db.tables[name.text]; !ok {
			return nil, 0, fmt.Errorf("no such table: %s", name.text)
		}
	} else if star {
		return nil, 0, fmt.Errorf("no tables specified")
	}
	var where expr
	if p.is("kw", "WHERE") {
		p.next()
		var err error
		if where, err = p.or(); err != nil {
			return nil, 0, err
		}
	}
	// Like a real database, reject unknown columns before running anything.
	for _, ref := range p.refs {
		known := false
		for _, c := range t.cols {
			if c == ref {
				known = true
			}
		}
		if !known {
			return nil, 0, fmt.Errorf("no such column: %s", ref)
		}
	}
	width := len(cols)
	if star {
		width = len(t.cols)
	}
	var out [][]any
	for _, vals := range t.rows {
		r := evalRow{cols: t.cols, vals: vals}
		if where != nil {
			v, err := where(r)
			if err != nil {
				return nil, 0, err
			}
			if !truthy(v) {
				continue
			}
		}
		if star {
			out = append(out, append([]any(nil), vals...))
			continue
		}
		row := make([]any, len(cols))
		for i, c := range cols {
			v, err := c(r)
			if err != nil {
				return nil, 0, err
			}
			row[i] = v
		}
		out = append(out, row)
	}
	return out, width, nil
}

func (p *sqlParser) or() (expr, error) {
	a, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.is("kw", "OR") {
		p.next()
		b, err := p.and()
		if err != nil {
			return nil, err
		}
		l, r := a, b
		a = func(row evalRow) (any, error) {
			x, err := l(row)
			if err != nil {
				return nil, err
			}
			if truthy(x) {
				return true, nil
			}
			y, err := r(row)
			return truthy(y), err
		}
	}
	return a, nil
}

func (p *sqlParser) and() (expr, error) {
	a, err := p.not()
	if err != nil {
		return nil, err
	}
	for p.is("kw", "AND") {
		p.next()
		b, err := p.not()
		if err != nil {
			return nil, err
		}
		l, r := a, b
		a = func(row evalRow) (any, error) {
			x, err := l(row)
			if err != nil || !truthy(x) {
				return false, err
			}
			y, err := r(row)
			return truthy(y), err
		}
	}
	return a, nil
}

func (p *sqlParser) not() (expr, error) {
	if p.is("kw", "NOT") {
		p.next()
		x, err := p.not()
		if err != nil {
			return nil, err
		}
		return func(row evalRow) (any, error) {
			v, err := x(row)
			return !truthy(v), err
		}, nil
	}
	return p.cmp()
}

func (p *sqlParser) cmp() (expr, error) {
	a, err := p.operand()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	op := ""
	switch {
	case t.kind == "sym" && (t.text == "=" || t.text == "!=" || t.text == "<>" || t.text == "<" || t.text == ">"):
		op = t.text
	case t.kind == "kw" && t.text == "LIKE":
		op = "LIKE"
	default:
		return a, nil
	}
	p.next()
	b, err := p.operand()
	if err != nil {
		return nil, err
	}
	return func(row evalRow) (any, error) {
		x, err := a(row)
		if err != nil {
			return nil, err
		}
		y, err := b(row)
		if err != nil {
			return nil, err
		}
		if x == nil || y == nil {
			return nil, nil
		}
		if op == "LIKE" {
			return like(show(x), show(y)), nil
		}
		c := compare(x, y)
		switch op {
		case "=":
			return c == 0, nil
		case "!=", "<>":
			return c != 0, nil
		case "<":
			return c < 0, nil
		default:
			return c > 0, nil
		}
	}, nil
}

func (p *sqlParser) operand() (expr, error) {
	t := p.next()
	switch {
	case t.kind == "str":
		v := t.text
		return func(evalRow) (any, error) { return v, nil }, nil
	case t.kind == "num":
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, syntaxErr(t)
		}
		return func(evalRow) (any, error) { return f, nil }, nil
	case t.kind == "kw" && t.text == "NULL":
		return func(evalRow) (any, error) { return nil, nil }, nil
	case t.kind == "ident":
		name := t.text
		p.refs = append(p.refs, name)
		return func(r evalRow) (any, error) {
			for i, c := range r.cols {
				if c == name {
					return r.vals[i], nil
				}
			}
			return nil, fmt.Errorf("no such column: %s", name)
		}, nil
	case t.kind == "sym" && t.text == "(":
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.is("sym", ")") {
			return nil, syntaxErr(p.peek())
		}
		p.next()
		return e, nil
	default:
		return nil, syntaxErr(t)
	}
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return err == nil && f != 0
	}
	return false
}

func compare(x, y any) int {
	if bx, ok := x.(bool); ok {
		x = map[bool]float64{true: 1, false: 0}[bx]
	}
	if by, ok := y.(bool); ok {
		y = map[bool]float64{true: 1, false: 0}[by]
	}
	fx, xNum := x.(float64)
	fy, yNum := y.(float64)
	switch {
	case xNum && yNum:
		switch {
		case fx < fy:
			return -1
		case fx > fy:
			return 1
		}
		return 0
	case xNum != yNum:
		// SQLite orders numbers before text.
		if xNum {
			return -1
		}
		return 1
	}
	return strings.Compare(show(x), show(y))
}

func show(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "1"
		}
		return "0"
	case string:
		return x
	}
	return fmt.Sprint(v)
}

func like(s, pattern string) bool {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(s)
}
