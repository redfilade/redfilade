// Package rules evaluates YARA-style text detection rules with Go's RE2
// engine, so hostile input cannot trigger catastrophic backtracking.
//
// Only the subset of YARA that text rules need is supported: meta values,
// regex and text strings, and conditions built from string references,
// "and", "or", "not", parentheses and "any of them" / "all of them".
// Anything else is a parse error: the engine fails closed rather than
// guessing what a rule means. The bundled rule set comes from Cisco's MCP
// Scanner (see cisco/SOURCE.md) and is checked against the reference YARA
// engine by the golden corpus in cisco/testdata.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// MaxInput bounds how much of one text a rule set scans.
const MaxInput = 64 << 10

// MaxOccurrences bounds how many matches of one string a loop condition
// enumerates. With MaxInput at 64 KiB it is never reached by the bundled
// rules, whose shortest loop string is longer than six bytes.
const MaxOccurrences = 10000

// Rule is one parsed rule.
type Rule struct {
	Name        string
	Description string
	ThreatType  string
	strs        map[string]*regexp.Regexp
	ctxRe       map[string]*regexp.Regexp // one character of left context, then the string
	startRe     map[string]*regexp.Regexp // the string anchored at offset 0
	order       []string
	cond        node
}

// Hit is one rule that matched a text.
type Hit struct {
	Rule        string
	Description string
	ThreatType  string
	Start, End  int // span of the first string that matched
}

// Set is an ordered collection of rules.
type Set struct{ rules []*Rule }

// Names returns the rule names in order.
func (s *Set) Names() []string {
	out := make([]string, len(s.rules))
	for i, r := range s.rules {
		out[i] = r.Name
	}
	return out
}

// Only returns the rules with the given names, in the set's order.
func (s *Set) Only(names ...string) *Set {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := &Set{}
	for _, r := range s.rules {
		if want[r.Name] {
			out.rules = append(out.rules, r)
		}
	}
	return out
}

// Match returns every rule that matches text.
func (s *Set) Match(text string) []Hit {
	if len(text) > MaxInput {
		text = text[:MaxInput]
	}
	var hits []Hit
	for _, r := range s.rules {
		found := map[string][]int{}
		for _, id := range r.order {
			if loc := r.strs[id].FindStringIndex(text); loc != nil {
				found[id] = loc
			}
		}
		ec := &evalCtx{r: r, text: text, found: found, occ: map[string][][2]int{}, vars: map[string]int{}}
		if r.cond.eval(ec) {
			h := Hit{Rule: r.Name, Description: r.Description, ThreatType: r.ThreatType, Start: -1, End: -1}
			for _, id := range r.order {
				if loc, ok := found[id]; ok {
					h.Start, h.End = loc[0], loc[1]
					break
				}
			}
			hits = append(hits, h)
		}
	}
	return hits
}

//go:embed cisco/*.yara
var ciscoFS embed.FS

var (
	ciscoOnce sync.Once
	ciscoSet  *Set
	ciscoErr  error
)

// Cisco returns the bundled Cisco MCP Scanner rules.
func Cisco() (*Set, error) {
	ciscoOnce.Do(func() { ciscoSet, ciscoErr = LoadFS(ciscoFS, "cisco") })
	return ciscoSet, ciscoErr
}

// LoadFS parses every *.yara file in dir, in name order.
func LoadFS(fsys fs.FS, dir string) (*Set, error) {
	names, err := fs.Glob(fsys, path.Join(dir, "*.yara"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	set := &Set{}
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		rs, err := Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		set.rules = append(set.rules, rs...)
	}
	if len(set.rules) == 0 {
		return nil, fmt.Errorf("no rules in %s", dir)
	}
	return set, nil
}

// --- lexer ------------------------------------------------------------------

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tVar
	tString
	tRegex
	tNumber
	tPunct
	tOcc // #name, @name or !name
)

type token struct {
	kind  tokKind
	text  string
	flags string // regex flags
	line  int
}

func lex(src string) ([]token, error) {
	var toks []token
	line := 1
	i := 0
	prevEq := false
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r':
			i++
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated comment", line)
			}
			line += strings.Count(src[i:i+2+end+2], "\n")
			i += 2 + end + 2
			continue
		}
		start := line
		switch {
		case c == '/' && prevEq:
			j := i + 1
			var b strings.Builder
			for ; j < len(src) && src[j] != '/'; j++ {
				if src[j] == '\n' {
					return nil, fmt.Errorf("line %d: newline in regex", line)
				}
				if src[j] == '\\' && j+1 < len(src) {
					b.WriteByte(src[j])
					j++
				}
				b.WriteByte(src[j])
			}
			if j >= len(src) {
				return nil, fmt.Errorf("line %d: unterminated regex", line)
			}
			j++
			k := j
			for k < len(src) && (src[k] == 'i' || src[k] == 's') {
				k++
			}
			toks = append(toks, token{kind: tRegex, text: b.String(), flags: src[j:k], line: start})
			i = k
		case c == '"':
			j := i + 1
			var b strings.Builder
			for ; j < len(src) && src[j] != '"'; j++ {
				if src[j] == '\\' && j+1 < len(src) {
					j++
					switch src[j] {
					case 'n':
						b.WriteByte('\n')
					case 't':
						b.WriteByte('\t')
					case '\\', '"':
						b.WriteByte(src[j])
					default:
						return nil, fmt.Errorf("line %d: unsupported escape \\%c", line, src[j])
					}
					continue
				}
				b.WriteByte(src[j])
			}
			if j >= len(src) {
				return nil, fmt.Errorf("line %d: unterminated string", line)
			}
			toks = append(toks, token{kind: tString, text: b.String(), line: start})
			i = j + 1
		case c == '$' || c == '_' || isAlpha(c):
			j := i + 1
			for j < len(src) && (isAlpha(src[j]) || isDigit(src[j]) || src[j] == '_') {
				j++
			}
			k := tIdent
			if c == '$' {
				k = tVar
			}
			toks = append(toks, token{kind: k, text: src[i:j], line: start})
			i = j
		case isDigit(c):
			j := i
			for j < len(src) && isDigit(src[j]) {
				j++
			}
			toks = append(toks, token{kind: tNumber, text: src[i:j], line: start})
			i = j
		case (c == '#' || c == '@' || c == '!') && i+1 < len(src) && (isAlpha(src[i+1]) || src[i+1] == '_'):
			j := i + 1
			for j < len(src) && (isAlpha(src[j]) || isDigit(src[j]) || src[j] == '_') {
				j++
			}
			toks = append(toks, token{kind: tOcc, text: src[i:j], line: start})
			i = j
		case c == '.' && i+1 < len(src) && src[i+1] == '.':
			toks = append(toks, token{kind: tPunct, text: "..", line: start})
			i += 2
		case (c == '<' || c == '>' || c == '=') && i+1 < len(src) && src[i+1] == '=':
			toks = append(toks, token{kind: tPunct, text: src[i : i+2], line: start})
			i += 2
		case strings.IndexByte("{}():=[]<>+", c) >= 0:
			toks = append(toks, token{kind: tPunct, text: string(c), line: start})
			i++
		default:
			return nil, fmt.Errorf("line %d: unexpected character %q", line, c)
		}
		prevEq = toks[len(toks)-1].kind == tPunct && toks[len(toks)-1].text == "="
	}
	toks = append(toks, token{kind: tEOF, line: line})
	return toks, nil
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// --- parser -----------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) expect(kind tokKind, text string) error {
	t := p.next()
	if t.kind != kind || (text != "" && t.text != text) {
		return fmt.Errorf("line %d: expected %q, got %q", t.line, text, t.text)
	}
	return nil
}

// Parse parses the rules in one source file.
func Parse(src string) ([]*Rule, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	var out []*Rule
	for p.peek().kind != tEOF {
		r, err := p.rule()
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (p *parser) rule() (*Rule, error) {
	if err := p.expect(tIdent, "rule"); err != nil {
		return nil, err
	}
	name := p.next()
	if name.kind != tIdent {
		return nil, fmt.Errorf("line %d: rule name expected", name.line)
	}
	if err := p.expect(tPunct, "{"); err != nil {
		return nil, err
	}
	r := &Rule{Name: name.text, strs: map[string]*regexp.Regexp{}, ctxRe: map[string]*regexp.Regexp{}, startRe: map[string]*regexp.Regexp{}}
	for {
		sec := p.next()
		if sec.kind != tIdent {
			return nil, fmt.Errorf("line %d: section expected", sec.line)
		}
		if err := p.expect(tPunct, ":"); err != nil {
			return nil, err
		}
		switch sec.text {
		case "meta":
			for p.peek().kind == tIdent && p.toks[p.pos+1].text == "=" {
				k := p.next().text
				p.next()
				v := p.next()
				if v.kind != tString && v.kind != tNumber && !(v.kind == tIdent && (v.text == "true" || v.text == "false")) {
					return nil, fmt.Errorf("line %d: bad meta value", v.line)
				}
				switch k {
				case "description":
					r.Description = v.text
				case "threat_type":
					r.ThreatType = v.text
				}
			}
		case "strings":
			for p.peek().kind == tVar {
				id := p.next()
				if err := p.expect(tPunct, "="); err != nil {
					return nil, err
				}
				if _, dup := r.strs[id.text]; dup {
					return nil, fmt.Errorf("line %d: duplicate string %s", id.line, id.text)
				}
				v := p.next()
				var expr string
				switch v.kind {
				case tRegex:
					expr = v.text
					for _, f := range v.flags {
						expr = "(?" + string(f) + ")" + expr
					}
				case tString:
					expr = regexp.QuoteMeta(v.text)
					if p.peek().kind == tIdent && p.peek().text == "nocase" {
						p.next()
						expr = "(?i)" + expr
					}
				default:
					return nil, fmt.Errorf("line %d: string value expected", v.line)
				}
				if p.peek().kind == tIdent && p.peek().text != "condition" && p.peek().text != "meta" {
					return nil, fmt.Errorf("line %d: unsupported string modifier %q", p.peek().line, p.peek().text)
				}
				re, err := regexp.Compile(expr)
				if err != nil {
					return nil, fmt.Errorf("line %d: %s: %w", v.line, id.text, err)
				}
				r.strs[id.text] = re
				r.ctxRe[id.text] = regexp.MustCompile(`(?s:.)(?:` + expr + `)`)
				r.startRe[id.text] = regexp.MustCompile(`\A(?:` + expr + `)`)
				r.order = append(r.order, id.text)
			}
		case "condition":
			n, err := p.or(r)
			if err != nil {
				return nil, err
			}
			r.cond = n
			if err := p.expect(tPunct, "}"); err != nil {
				return nil, err
			}
			if r.cond == nil {
				return nil, fmt.Errorf("rule %s: empty condition", r.Name)
			}
			return r, nil
		default:
			return nil, fmt.Errorf("line %d: unsupported section %q", sec.line, sec.text)
		}
	}
}

// --- conditions -------------------------------------------------------------

type evalCtx struct {
	r     *Rule
	text  string
	found map[string][]int
	occ   map[string][][2]int
	vars  map[string]int
}

// occurrences lists every match of a string the way YARA does: one match per
// starting offset, overlapping matches included, each found with its left
// context so word boundaries behave as they do in a full scan.
func (c *evalCtx) occurrences(id string) [][2]int {
	if o, ok := c.occ[id]; ok {
		return o
	}
	var out [][2]int
	if _, ok := c.found[id]; ok {
		if loc := c.r.startRe[id].FindStringIndex(c.text); loc != nil {
			out = append(out, [2]int{0, loc[1]})
		}
		for s0 := 1; s0 < len(c.text) && len(out) < MaxOccurrences; {
			loc := c.r.ctxRe[id].FindStringIndex(c.text[s0-1:])
			if loc == nil {
				break
			}
			q := s0 - 1 + loc[0]
			_, w := utf8.DecodeRuneInString(c.text[q:])
			start, end := q+w, s0-1+loc[1]
			out = append(out, [2]int{start, end})
			s0 = start + 1
		}
	}
	c.occ[id] = out
	return out
}

type node interface{ eval(c *evalCtx) bool }

type ref string
type notNode struct{ x node }
type andNode struct{ a, b node }
type orNode struct{ a, b node }
type ofThem struct{ all bool }

func (n ref) eval(c *evalCtx) bool     { _, ok := c.found[string(n)]; return ok }
func (n notNode) eval(c *evalCtx) bool { return !n.x.eval(c) }
func (n andNode) eval(c *evalCtx) bool { return n.a.eval(c) && n.b.eval(c) }
func (n orNode) eval(c *evalCtx) bool  { return n.a.eval(c) || n.b.eval(c) }
func (n ofThem) eval(c *evalCtx) bool {
	if n.all {
		return len(c.r.order) > 0 && len(c.found) == len(c.r.order)
	}
	return len(c.found) > 0
}

// forNode is "for any|all VAR in (LO..#str) : (body)".
type forNode struct {
	all  bool
	v    string
	lo   int
	str  string
	body node
}

func (n forNode) eval(c *evalCtx) bool {
	hi := len(c.occurrences(n.str))
	if hi < n.lo {
		return n.all
	}
	saved, had := c.vars[n.v]
	defer func() {
		if had {
			c.vars[n.v] = saved
		} else {
			delete(c.vars, n.v)
		}
	}()
	for i := n.lo; i <= hi; i++ {
		c.vars[n.v] = i
		ok := n.body.eval(c)
		if ok && !n.all {
			return true
		}
		if !ok && n.all {
			return false
		}
	}
	return n.all
}

// num is an integer expression; ok is false when it is undefined, which makes
// any comparison using it false, as in YARA.
type num interface{ val(c *evalCtx) (int, bool) }

type lit int
type count string
type occAt struct {
	kind byte // '@' offset or '!' length
	str  string
	idx  num
}
type plus struct{ a, b num }
type varRef string

func (n lit) val(*evalCtx) (int, bool)      { return int(n), true }
func (n count) val(c *evalCtx) (int, bool)  { return len(c.occurrences(string(n))), true }
func (n varRef) val(c *evalCtx) (int, bool) { v, ok := c.vars[string(n)]; return v, ok }
func (n plus) val(c *evalCtx) (int, bool) {
	a, ok1 := n.a.val(c)
	b, ok2 := n.b.val(c)
	return a + b, ok1 && ok2
}
func (n occAt) val(c *evalCtx) (int, bool) {
	i, ok := n.idx.val(c)
	o := c.occurrences(n.str)
	if !ok || i < 1 || i > len(o) {
		return 0, false
	}
	if n.kind == '@' {
		return o[i-1][0], true
	}
	return o[i-1][1] - o[i-1][0], true
}

type cmp struct {
	op   string
	a, b num
}

func (n cmp) eval(c *evalCtx) bool {
	a, ok1 := n.a.val(c)
	b, ok2 := n.b.val(c)
	if !ok1 || !ok2 {
		return false
	}
	switch n.op {
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	default:
		return a == b
	}
}

func (p *parser) or(r *Rule) (node, error) { return p.orIn(r, scope{}) }

func (p *parser) strRef(r *Rule, t token) (string, error) {
	id := "$" + t.text[1:]
	if _, ok := r.strs[id]; !ok {
		return "", fmt.Errorf("line %d: undefined string %s", t.line, id)
	}
	return id, nil
}

// numeric parses a sum of terms: INT, VAR, #s, @s[expr], !s[expr].
func (p *parser) numeric(r *Rule, vars map[string]bool) (num, error) {
	a, err := p.term(r, vars)
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tPunct && p.peek().text == "+" {
		p.next()
		b, err := p.term(r, vars)
		if err != nil {
			return nil, err
		}
		a = plus{a, b}
	}
	return a, nil
}

func (p *parser) term(r *Rule, vars map[string]bool) (num, error) {
	t := p.next()
	switch {
	case t.kind == tNumber:
		v, err := strconv.Atoi(t.text)
		if err != nil {
			return nil, err
		}
		return lit(v), nil
	case t.kind == tIdent && vars[t.text]:
		return varRef(t.text), nil
	case t.kind == tOcc && t.text[0] == '#':
		id, err := p.strRef(r, t)
		if err != nil {
			return nil, err
		}
		return count(id), nil
	case t.kind == tOcc:
		id, err := p.strRef(r, t)
		if err != nil {
			return nil, err
		}
		if err := p.expect(tPunct, "["); err != nil {
			return nil, err
		}
		idx, err := p.numeric(r, vars)
		if err != nil {
			return nil, err
		}
		if err := p.expect(tPunct, "]"); err != nil {
			return nil, err
		}
		return occAt{kind: t.text[0], str: id, idx: idx}, nil
	default:
		return nil, fmt.Errorf("line %d: unsupported number element %q", t.line, t.text)
	}
}

// vars in scope for loop bodies, tracked while parsing.
type scope map[string]bool

func (p *parser) unaryIn(r *Rule, vars scope) (node, error) {
	t := p.peek()
	switch {
	case t.kind == tIdent && t.text == "not":
		p.next()
		x, err := p.unaryIn(r, vars)
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	case t.kind == tPunct && t.text == "(":
		p.next()
		x, err := p.orIn(r, vars)
		if err != nil {
			return nil, err
		}
		if err := p.expect(tPunct, ")"); err != nil {
			return nil, err
		}
		return x, nil
	case t.kind == tVar:
		p.next()
		if _, ok := r.strs[t.text]; !ok {
			return nil, fmt.Errorf("line %d: undefined string %s", t.line, t.text)
		}
		return ref(t.text), nil
	case t.kind == tIdent && t.text == "for":
		return p.forLoop(r, vars)
	case t.kind == tIdent && (t.text == "any" || t.text == "all"):
		p.next()
		if err := p.expect(tIdent, "of"); err != nil {
			return nil, err
		}
		if err := p.expect(tIdent, "them"); err != nil {
			return nil, err
		}
		return ofThem{all: t.text == "all"}, nil
	case t.kind == tNumber || t.kind == tOcc || (t.kind == tIdent && vars[t.text]):
		a, err := p.numeric(r, vars)
		if err != nil {
			return nil, err
		}
		op := p.next()
		switch op.text {
		case "<", "<=", ">", ">=", "==":
		default:
			return nil, fmt.Errorf("line %d: comparison expected, got %q", op.line, op.text)
		}
		b, err := p.numeric(r, vars)
		if err != nil {
			return nil, err
		}
		return cmp{op: op.text, a: a, b: b}, nil
	default:
		p.next()
		return nil, fmt.Errorf("line %d: unsupported condition element %q", t.line, t.text)
	}
}

func (p *parser) forLoop(r *Rule, vars scope) (node, error) {
	p.next() // for
	q := p.next()
	if q.kind != tIdent || (q.text != "any" && q.text != "all") {
		return nil, fmt.Errorf("line %d: for any|all expected", q.line)
	}
	v := p.next()
	if v.kind != tIdent || v.text == "of" {
		return nil, fmt.Errorf("line %d: loop variable expected", v.line)
	}
	if err := p.expect(tIdent, "in"); err != nil {
		return nil, err
	}
	if err := p.expect(tPunct, "("); err != nil {
		return nil, err
	}
	lo := p.next()
	if lo.kind != tNumber {
		return nil, fmt.Errorf("line %d: range start must be a number", lo.line)
	}
	if err := p.expect(tPunct, ".."); err != nil {
		return nil, err
	}
	hi := p.next()
	if hi.kind != tOcc || hi.text[0] != '#' {
		return nil, fmt.Errorf("line %d: range end must be #string", hi.line)
	}
	id, err := p.strRef(r, hi)
	if err != nil {
		return nil, err
	}
	if err := p.expect(tPunct, ")"); err != nil {
		return nil, err
	}
	if err := p.expect(tPunct, ":"); err != nil {
		return nil, err
	}
	inner := scope{}
	for k := range vars {
		inner[k] = true
	}
	inner[v.text] = true
	body, err := p.unaryIn(r, inner)
	if err != nil {
		return nil, err
	}
	n, _ := strconv.Atoi(lo.text)
	return forNode{all: q.text == "all", v: v.text, lo: n, str: id, body: body}, nil
}

func (p *parser) orIn(r *Rule, vars scope) (node, error) {
	a, err := p.andIn(r, vars)
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tIdent && p.peek().text == "or" {
		p.next()
		b, err := p.andIn(r, vars)
		if err != nil {
			return nil, err
		}
		a = orNode{a, b}
	}
	return a, nil
}

func (p *parser) andIn(r *Rule, vars scope) (node, error) {
	a, err := p.unaryIn(r, vars)
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tIdent && p.peek().text == "and" {
		p.next()
		b, err := p.unaryIn(r, vars)
		if err != nil {
			return nil, err
		}
		a = andNode{a, b}
	}
	return a, nil
}
