package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

const endSymbol rune = 1114112

/* The rule types inferred from the grammar are below. */
type pegRule uint8

const (
	ruleUnknown pegRule = iota
	ruleAsmFile
	ruleStatement
	ruleGlobalDirective
	ruleDirective
	ruleDirectiveName
	ruleLocationDirective
	ruleArgs
	ruleArg
	ruleQuotedArg
	ruleQuotedText
	ruleLabelContainingDirective
	ruleLabelContainingDirectiveName
	ruleSymbolArgs
	ruleSymbolArg
	ruleSymbolType
	ruleDot
	ruleTCMarker
	ruleEscapedChar
	ruleWS
	ruleComment
	ruleLabel
	ruleSymbolName
	ruleLocalSymbol
	ruleLocalLabel
	ruleLocalLabelRef
	ruleInstruction
	ruleInstructionName
	ruleInstructionArg
	ruleTOCRefHigh
	ruleTOCRefLow
	ruleIndirectionIndicator
	ruleRegisterOrConstant
	ruleMemoryRef
	ruleSymbolRef
	ruleBaseIndexScale
	ruleOperator
	ruleOffset
	ruleSection
	ruleSegmentRegister
)

var rul3s = [...]string{
	"Unknown",
	"AsmFile",
	"Statement",
	"GlobalDirective",
	"Directive",
	"DirectiveName",
	"LocationDirective",
	"Args",
	"Arg",
	"QuotedArg",
	"QuotedText",
	"LabelContainingDirective",
	"LabelContainingDirectiveName",
	"SymbolArgs",
	"SymbolArg",
	"SymbolType",
	"Dot",
	"TCMarker",
	"EscapedChar",
	"WS",
	"Comment",
	"Label",
	"SymbolName",
	"LocalSymbol",
	"LocalLabel",
	"LocalLabelRef",
	"Instruction",
	"InstructionName",
	"InstructionArg",
	"TOCRefHigh",
	"TOCRefLow",
	"IndirectionIndicator",
	"RegisterOrConstant",
	"MemoryRef",
	"SymbolRef",
	"BaseIndexScale",
	"Operator",
	"Offset",
	"Section",
	"SegmentRegister",
}

type token32 struct {
	pegRule
	begin, end uint32
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v", rul3s[t.pegRule], t.begin, t.end)
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(pretty bool, buffer string) {
	var print func(node *node32, depth int)
	print = func(node *node32, depth int) {
		for node != nil {
			for c := 0; c < depth; c++ {
				fmt.Printf(" ")
			}
			rule := rul3s[node.pegRule]
			quote := strconv.Quote(string(([]rune(buffer)[node.begin:node.end])))
			if !pretty {
				fmt.Printf("%v %v\n", rule, quote)
			} else {
				fmt.Printf("\x1B[34m%v\x1B[m %v\n", rule, quote)
			}
			if node.up != nil {
				print(node.up, depth+1)
			}
			node = node.next
		}
	}
	print(node, 0)
}

func (node *node32) Print(buffer string) {
	node.print(false, buffer)
}

func (node *node32) PrettyPrint(buffer string) {
	node.print(true, buffer)
}

type tokens32 struct {
	tree []token32
}

func (t *tokens32) Trim(length uint32) {
	t.tree = t.tree[:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) AST() *node32 {
	type element struct {
		node *node32
		down *element
	}
	tokens := t.Tokens()
	var stack *element
	for _, token := range tokens {
		if token.begin == token.end {
			continue
		}
		node := &node32{token32: token}
		for stack != nil && stack.node.begin >= token.begin && stack.node.end <= token.end {
			stack.node.next = node.up
			node.up = stack.node
			stack = stack.down
		}
		stack = &element{node: node, down: stack}
	}
	if stack != nil {
		return stack.node
	}
	return nil
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	t.AST().Print(buffer)
}

func (t *tokens32) PrettyPrintSyntaxTree(buffer string) {
	t.AST().PrettyPrint(buffer)
}

func (t *tokens32) Add(rule pegRule, begin, end, index uint32) {
	if tree := t.tree; int(index) >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
	t.tree[index] = token32{
		pegRule: rule,
		begin:   begin,
		end:     end,
	}
}

func (t *tokens32) Tokens() []token32 {
	return t.tree
}

type Asm struct {
	Buffer string
	buffer []rune
	rules  [40]func() bool
	parse  func(rule ...int) error
	reset  func()
	Pretty bool
	tokens32
}

func (p *Asm) Parse(rule ...int) error {
	return p.parse(rule...)
}

func (p *Asm) Reset() {
	p.reset()
}

type textPosition struct {
	line, symbol int
}

type textPositionMap map[int]textPosition

func translatePositions(buffer []rune, positions []int) textPositionMap {
	length, translations, j, line, symbol := len(positions), make(textPositionMap, len(positions)), 0, 1, 0
	sort.Ints(positions)

search:
	for i, c := range buffer {
		if c == '\n' {
			line, symbol = line+1, 0
		} else {
			symbol++
		}
		if i == positions[j] {
			translations[positions[j]] = textPosition{line, symbol}
			for j++; j < length; j++ {
				if i != positions[j] {
					continue search
				}
			}
			break search
		}
	}

	return translations
}

type parseError struct {
	p   *Asm
	max token32
}

func (e *parseError) Error() string {
	tokens, error := []token32{e.max}, "\n"
	positions, p := make([]int, 2*len(tokens)), 0
	for _, token := range tokens {
		positions[p], p = int(token.begin), p+1
		positions[p], p = int(token.end), p+1
	}
	translations := translatePositions(e.p.buffer, positions)
	format := "parse error near %v (line %v symbol %v - line %v symbol %v):\n%v\n"
	if e.p.Pretty {
		format = "parse error near \x1B[34m%v\x1B[m (line %v symbol %v - line %v symbol %v):\n%v\n"
	}
	for _, token := range tokens {
		begin, end := int(token.begin), int(token.end)
		error += fmt.Sprintf(format,
			rul3s[token.pegRule],
			translations[begin].line, translations[begin].symbol,
			translations[end].line, translations[end].symbol,
			strconv.Quote(string(e.p.buffer[begin:end])))
	}

	return error
}

func (p *Asm) PrintSyntaxTree() {
	if p.Pretty {
		p.tokens32.PrettyPrintSyntaxTree(p.Buffer)
	} else {
		p.tokens32.PrintSyntaxTree(p.Buffer)
	}
}

func (p *Asm) Init() {
	var (
		max                  token32
		position, tokenIndex uint32
		buffer               []rune
	)
	p.reset = func() {
		max = token32{}
		position, tokenIndex = 0, 0

		p.buffer = []rune(p.Buffer)
		if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != endSymbol {
			p.buffer = append(p.buffer, endSymbol)
		}
		buffer = p.buffer
	}
	p.reset()

	_rules := p.rules
	tree := tokens32{tree: make([]token32, math.MaxInt16)}
	p.parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokens32 = tree
		if matches {
			p.Trim(tokenIndex)
			return nil
		}
		return &parseError{p, max}
	}

	add := func(rule pegRule, begin uint32) {
		tree.Add(rule, begin, position, tokenIndex)
		tokenIndex++
		if begin != position && position > max.end {
			max = token32{rule, begin, position}
		}
	}

	matchDot := func() bool {
		if buffer[position] != endSymbol {
			position++
			return true
		}
		return false
	}

	/*matchChar := func(c byte) bool {
		if buffer[position] == c {
			position++
			return true
		}
		return false
	}*/

	/*matchRange := func(lower byte, upper byte) bool {
		if c := buffer[position]; c >= lower && c <= upper {
			position++
			return true
		}
		return false
	}*/

	_rules = [...]func() bool{
		nil,
		/* 0 AsmFile <- <(Statement* !.)> */
		func() bool {
			position0, tokenIndex0 := position, tokenIndex
			{
				position1 := position
			l2:
				{
					position3, tokenIndex3 := position, tokenIndex
					if !_rules[ruleStatement]() {
						goto l3
					}
					goto l2
				l3:
					position, tokenIndex = position3, tokenIndex3
				}
				{
					position4, tokenIndex4 := position, tokenIndex
					if !matchDot() {
						goto l4
					}
					goto l0
				l4:
					position, tokenIndex = position4, tokenIndex4
				}
				add(ruleAsmFile, position1)
			}
			return true
		l0:
			position, tokenIndex = position0, tokenIndex0
			return false
		},
		/* 1 Statement <- <(WS? (Label / ((GlobalDirective / LocationDirective / LabelContainingDirective / Instruction / Directive / Comment / ) WS? ((Comment? '\n') / ';'))))> */
		func() bool {
			position5, tokenIndex5 := position, tokenIndex
			{
				position6 := position
				{
					position7, tokenIndex7 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l7
					}
					goto l8
				l7:
					position, tokenIndex = position7, tokenIndex7
				}
			l8:
				{
					position9, tokenIndex9 := position, tokenIndex
					if !_rules[ruleLabel]() {
						goto l10
					}
					goto l9
				l10:
					position, tokenIndex = position9, tokenIndex9
					{
						position11, tokenIndex11 := position, tokenIndex
						if !_rules[ruleGlobalDirective]() {
							goto l12
						}
						goto l11
					l12:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLocationDirective]() {
							goto l13
						}
						goto l11
					l13:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLabelContainingDirective]() {
							goto l14
						}
						goto l11
					l14:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleInstruction]() {
							goto l15
						}
						goto l11
					l15:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleDirective]() {
							goto l16
						}
						goto l11
					l16:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleComment]() {
							goto l17
						}
						goto l11
					l17:
						position, tokenIndex = position11, tokenIndex11
					}
				l11:
					{
						position18, tokenIndex18 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l18
						}
						goto l19
					l18:
						position, tokenIndex = position18, tokenIndex18
					}
				l19:
					{
						position20, tokenIndex20 := position, tokenIndex
						{
							position22, tokenIndex22 := position, tokenIndex
							if !_rules[ruleComment]() {
								goto l22
							}
							goto l23
						l22:
							position, tokenIndex = position22, tokenIndex22
						}
					l23:
						if buffer[position] != rune('\n') {
							goto l21
						}
						position++
						goto l20
					l21:
						position, tokenIndex = position20, tokenIndex20
						if buffer[position] != rune(';') {
							goto l5
						}
						position++
					}
				l20:
				}
			l9:
				add(ruleStatement, position6)
			}
			return true
		l5:
			position, tokenIndex = position5, tokenIndex5
			return false
		},
		/* 2 GlobalDirective <- <((('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('a' / 'A') ('l' / 'L')) / ('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('l' / 'L'))) WS SymbolName)> */
		func() bool {
			position24, tokenIndex24 := position, tokenIndex
			{
				position25 := position
				{
					position26, tokenIndex26 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l27
					}
					position++
					{
						position28, tokenIndex28 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l29
						}
						position++
						goto l28
					l29:
						position, tokenIndex = position28, tokenIndex28
						if buffer[position] != rune('G') {
							goto l27
						}
						position++
					}
				l28:
					{
						position30, tokenIndex30 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l31
						}
						position++
						goto l30
					l31:
						position, tokenIndex = position30, tokenIndex30
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l30:
					{
						position32, tokenIndex32 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l33
						}
						position++
						goto l32
					l33:
						position, tokenIndex = position32, tokenIndex32
						if buffer[position] != rune('O') {
							goto l27
						}
						position++
					}
				l32:
					{
						position34, tokenIndex34 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l35
						}
						position++
						goto l34
					l35:
						position, tokenIndex = position34, tokenIndex34
						if buffer[position] != rune('B') {
							goto l27
						}
						position++
					}
				l34:
					{
						position36, tokenIndex36 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l37
						}
						position++
						goto l36
					l37:
						position, tokenIndex = position36, tokenIndex36
						if buffer[position] != rune('A') {
							goto l27
						}
						position++
					}
				l36:
					{
						position38, tokenIndex38 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l39
						}
						position++
						goto l38
					l39:
						position, tokenIndex = position38, tokenIndex38
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l38:
					goto l26
				l27:
					position, tokenIndex = position26, tokenIndex26
					if buffer[position] != rune('.') {
						goto l24
					}
					position++
					{
						position40, tokenIndex40 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l41
						}
						position++
						goto l40
					l41:
						position, tokenIndex = position40, tokenIndex40
						if buffer[position] != rune('G') {
							goto l24
						}
						position++
					}
				l40:
					{
						position42, tokenIndex42 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l43
						}
						position++
						goto l42
					l43:
						position, tokenIndex = position42, tokenIndex42
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l42:
					{
						position44, tokenIndex44 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l45
						}
						position++
						goto l44
					l45:
						position, tokenIndex = position44, tokenIndex44
						if buffer[position] != rune('O') {
							goto l24
						}
						position++
					}
				l44:
					{
						position46, tokenIndex46 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l47
						}
						position++
						goto l46
					l47:
						position, tokenIndex = position46, tokenIndex46
						if buffer[position] != rune('B') {
							goto l24
						}
						position++
					}
				l46:
					{
						position48, tokenIndex48 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l49
						}
						position++
						goto l48
					l49:
						position, tokenIndex = position48, tokenIndex48
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l48:
				}
			l26:
				if !_rules[ruleWS]() {
					goto l24
				}
				if !_rules[ruleSymbolName]() {
					goto l24
				}
				add(ruleGlobalDirective, position25)
			}
			return true
		l24:
			position, tokenIndex = position24, tokenIndex24
			return false
		},
		/* 3 Directive <- <('.' DirectiveName (WS Args)?)> */
		func() bool {
			position50, tokenIndex50 := position, tokenIndex
			{
				position51 := position
				if buffer[position] != rune('.') {
					goto l50
				}
				position++
				if !_rules[ruleDirectiveName]() {
					goto l50
				}
				{
					position52, tokenIndex52 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l52
					}
					if !_rules[ruleArgs]() {
						goto l52
					}
					goto l53
				l52:
					position, tokenIndex = position52, tokenIndex52
				}
			l53:
				add(ruleDirective, position51)
			}
			return true
		l50:
			position, tokenIndex = position50, tokenIndex50
			return false
		},
		/* 4 DirectiveName <- <([a-z] / [A-Z] / ([0-9] / [0-9]) / '_')+> */
		func() bool {
			position54, tokenIndex54 := position, tokenIndex
			{
				position55 := position
				{
					position58, tokenIndex58 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l59
					}
					position++
					goto l58
				l59:
					position, tokenIndex = position58, tokenIndex58
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l60
					}
					position++
					goto l58
				l60:
					position, tokenIndex = position58, tokenIndex58
					{
						position62, tokenIndex62 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l63
						}
						position++
						goto l62
					l63:
						position, tokenIndex = position62, tokenIndex62
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l61
						}
						position++
					}
				l62:
					goto l58
				l61:
					position, tokenIndex = position58, tokenIndex58
					if buffer[position] != rune('_') {
						goto l54
					}
					position++
				}
			l58:
			l56:
				{
					position57, tokenIndex57 := position, tokenIndex
					{
						position64, tokenIndex64 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l65
						}
						position++
						goto l64
					l65:
						position, tokenIndex = position64, tokenIndex64
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l66
						}
						position++
						goto l64
					l66:
						position, tokenIndex = position64, tokenIndex64
						{
							position68, tokenIndex68 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l69
							}
							position++
							goto l68
						l69:
							position, tokenIndex = position68, tokenIndex68
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l67
							}
							position++
						}
					l68:
						goto l64
					l67:
						position, tokenIndex = position64, tokenIndex64
						if buffer[position] != rune('_') {
							goto l57
						}
						position++
					}
				l64:
					goto l56
				l57:
					position, tokenIndex = position57, tokenIndex57
				}
				add(ruleDirectiveName, position55)
			}
			return true
		l54:
			position, tokenIndex = position54, tokenIndex54
			return false
		},
		/* 5 LocationDirective <- <((('.' ('f' / 'F') ('i' / 'I') ('l' / 'L') ('e' / 'E')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C'))) WS (!('#' / '\n') .)+)> */
		func() bool {
			position70, tokenIndex70 := position, tokenIndex
			{
				position71 := position
				{
					position72, tokenIndex72 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l73
					}
					position++
					{
						position74, tokenIndex74 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l75
						}
						position++
						goto l74
					l75:
						position, tokenIndex = position74, tokenIndex74
						if buffer[position] != rune('F') {
							goto l73
						}
						position++
					}
				l74:
					{
						position76, tokenIndex76 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l77
						}
						position++
						goto l76
					l77:
						position, tokenIndex = position76, tokenIndex76
						if buffer[position] != rune('I') {
							goto l73
						}
						position++
					}
				l76:
					{
						position78, tokenIndex78 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l79
						}
						position++
						goto l78
					l79:
						position, tokenIndex = position78, tokenIndex78
						if buffer[position] != rune('L') {
							goto l73
						}
						position++
					}
				l78:
					{
						position80, tokenIndex80 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l81
						}
						position++
						goto l80
					l81:
						position, tokenIndex = position80, tokenIndex80
						if buffer[position] != rune('E') {
							goto l73
						}
						position++
					}
				l80:
					goto l72
				l73:
					position, tokenIndex = position72, tokenIndex72
					if buffer[position] != rune('.') {
						goto l70
					}
					position++
					{
						position82, tokenIndex82 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l83
						}
						position++
						goto l82
					l83:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('L') {
							goto l70
						}
						position++
					}
				l82:
					{
						position84, tokenIndex84 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l85
						}
						position++
						goto l84
					l85:
						position, tokenIndex = position84, tokenIndex84
						if buffer[position] != rune('O') {
							goto l70
						}
						position++
					}
				l84:
					{
						position86, tokenIndex86 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l87
						}
						position++
						goto l86
					l87:
						position, tokenIndex = position86, tokenIndex86
						if buffer[position] != rune('C') {
							goto l70
						}
						position++
					}
				l86:
				}
			l72:
				if !_rules[ruleWS]() {
					goto l70
				}
				{
					position90, tokenIndex90 := position, tokenIndex
					{
						position91, tokenIndex91 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l92
						}
						position++
						goto l91
					l92:
						position, tokenIndex = position91, tokenIndex91
						if buffer[position] != rune('\n') {
							goto l90
						}
						position++
					}
				l91:
					goto l70
				l90:
					position, tokenIndex = position90, tokenIndex90
				}
				if !matchDot() {
					goto l70
				}
			l88:
				{
					position89, tokenIndex89 := position, tokenIndex
					{
						position93, tokenIndex93 := position, tokenIndex
						{
							position94, tokenIndex94 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l95
							}
							position++
							goto l94
						l95:
							position, tokenIndex = position94, tokenIndex94
							if buffer[position] != rune('\n') {
								goto l93
							}
							position++
						}
					l94:
						goto l89
					l93:
						position, tokenIndex = position93, tokenIndex93
					}
					if !matchDot() {
						goto l89
					}
					goto l88
				l89:
					position, tokenIndex = position89, tokenIndex89
				}
				add(ruleLocationDirective, position71)
			}
			return true
		l70:
			position, tokenIndex = position70, tokenIndex70
			return false
		},
		/* 6 Args <- <(Arg (WS? ',' WS? Arg)*)> */
		func() bool {
			position96, tokenIndex96 := position, tokenIndex
			{
				position97 := position
				if !_rules[ruleArg]() {
					goto l96
				}
			l98:
				{
					position99, tokenIndex99 := position, tokenIndex
					{
						position100, tokenIndex100 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l100
						}
						goto l101
					l100:
						position, tokenIndex = position100, tokenIndex100
					}
				l101:
					if buffer[position] != rune(',') {
						goto l99
					}
					position++
					{
						position102, tokenIndex102 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l102
						}
						goto l103
					l102:
						position, tokenIndex = position102, tokenIndex102
					}
				l103:
					if !_rules[ruleArg]() {
						goto l99
					}
					goto l98
				l99:
					position, tokenIndex = position99, tokenIndex99
				}
				add(ruleArgs, position97)
			}
			return true
		l96:
			position, tokenIndex = position96, tokenIndex96
			return false
		},
		/* 7 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '_' / '@' / '.')*)> */
		func() bool {
			{
				position105 := position
				{
					position106, tokenIndex106 := position, tokenIndex
					if !_rules[ruleQuotedArg]() {
						goto l107
					}
					goto l106
				l107:
					position, tokenIndex = position106, tokenIndex106
				l108:
					{
						position109, tokenIndex109 := position, tokenIndex
						{
							position110, tokenIndex110 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l111
							}
							position++
							goto l110
						l111:
							position, tokenIndex = position110, tokenIndex110
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l112
							}
							position++
							goto l110
						l112:
							position, tokenIndex = position110, tokenIndex110
							{
								position114, tokenIndex114 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l115
								}
								position++
								goto l114
							l115:
								position, tokenIndex = position114, tokenIndex114
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l113
								}
								position++
							}
						l114:
							goto l110
						l113:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('%') {
								goto l116
							}
							position++
							goto l110
						l116:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('+') {
								goto l117
							}
							position++
							goto l110
						l117:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('-') {
								goto l118
							}
							position++
							goto l110
						l118:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('_') {
								goto l119
							}
							position++
							goto l110
						l119:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('@') {
								goto l120
							}
							position++
							goto l110
						l120:
							position, tokenIndex = position110, tokenIndex110
							if buffer[position] != rune('.') {
								goto l109
							}
							position++
						}
					l110:
						goto l108
					l109:
						position, tokenIndex = position109, tokenIndex109
					}
				}
			l106:
				add(ruleArg, position105)
			}
			return true
		},
		/* 8 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position121, tokenIndex121 := position, tokenIndex
			{
				position122 := position
				if buffer[position] != rune('"') {
					goto l121
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l121
				}
				if buffer[position] != rune('"') {
					goto l121
				}
				position++
				add(ruleQuotedArg, position122)
			}
			return true
		l121:
			position, tokenIndex = position121, tokenIndex121
			return false
		},
		/* 9 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position124 := position
			l125:
				{
					position126, tokenIndex126 := position, tokenIndex
					{
						position127, tokenIndex127 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l128
						}
						goto l127
					l128:
						position, tokenIndex = position127, tokenIndex127
						{
							position129, tokenIndex129 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l129
							}
							position++
							goto l126
						l129:
							position, tokenIndex = position129, tokenIndex129
						}
						if !matchDot() {
							goto l126
						}
					}
				l127:
					goto l125
				l126:
					position, tokenIndex = position126, tokenIndex126
				}
				add(ruleQuotedText, position124)
			}
			return true
		},
		/* 10 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position130, tokenIndex130 := position, tokenIndex
			{
				position131 := position
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l130
				}
				if !_rules[ruleWS]() {
					goto l130
				}
				if !_rules[ruleSymbolArgs]() {
					goto l130
				}
				add(ruleLabelContainingDirective, position131)
			}
			return true
		l130:
			position, tokenIndex = position130, tokenIndex130
			return false
		},
		/* 11 LabelContainingDirectiveName <- <(('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')) / ('.' ('t' / 'T') ('c' / 'C')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') ('a' / 'A') ('l' / 'L') ('e' / 'E') ('n' / 'N') ('t' / 'T') ('r' / 'R') ('y' / 'Y')) / ('.' ('s' / 'S') ('i' / 'I') ('z' / 'Z') ('e' / 'E')) / ('.' ('t' / 'T') ('y' / 'Y') ('p' / 'P') ('e' / 'E')))> */
		func() bool {
			position132, tokenIndex132 := position, tokenIndex
			{
				position133 := position
				{
					position134, tokenIndex134 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l135
					}
					position++
					{
						position136, tokenIndex136 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l137
						}
						position++
						goto l136
					l137:
						position, tokenIndex = position136, tokenIndex136
						if buffer[position] != rune('L') {
							goto l135
						}
						position++
					}
				l136:
					{
						position138, tokenIndex138 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l139
						}
						position++
						goto l138
					l139:
						position, tokenIndex = position138, tokenIndex138
						if buffer[position] != rune('O') {
							goto l135
						}
						position++
					}
				l138:
					{
						position140, tokenIndex140 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l141
						}
						position++
						goto l140
					l141:
						position, tokenIndex = position140, tokenIndex140
						if buffer[position] != rune('N') {
							goto l135
						}
						position++
					}
				l140:
					{
						position142, tokenIndex142 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l143
						}
						position++
						goto l142
					l143:
						position, tokenIndex = position142, tokenIndex142
						if buffer[position] != rune('G') {
							goto l135
						}
						position++
					}
				l142:
					goto l134
				l135:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l144
					}
					position++
					{
						position145, tokenIndex145 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l146
						}
						position++
						goto l145
					l146:
						position, tokenIndex = position145, tokenIndex145
						if buffer[position] != rune('S') {
							goto l144
						}
						position++
					}
				l145:
					{
						position147, tokenIndex147 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l148
						}
						position++
						goto l147
					l148:
						position, tokenIndex = position147, tokenIndex147
						if buffer[position] != rune('E') {
							goto l144
						}
						position++
					}
				l147:
					{
						position149, tokenIndex149 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l150
						}
						position++
						goto l149
					l150:
						position, tokenIndex = position149, tokenIndex149
						if buffer[position] != rune('T') {
							goto l144
						}
						position++
					}
				l149:
					goto l134
				l144:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l151
					}
					position++
					if buffer[position] != rune('8') {
						goto l151
					}
					position++
					{
						position152, tokenIndex152 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l153
						}
						position++
						goto l152
					l153:
						position, tokenIndex = position152, tokenIndex152
						if buffer[position] != rune('B') {
							goto l151
						}
						position++
					}
				l152:
					{
						position154, tokenIndex154 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l155
						}
						position++
						goto l154
					l155:
						position, tokenIndex = position154, tokenIndex154
						if buffer[position] != rune('Y') {
							goto l151
						}
						position++
					}
				l154:
					{
						position156, tokenIndex156 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l157
						}
						position++
						goto l156
					l157:
						position, tokenIndex = position156, tokenIndex156
						if buffer[position] != rune('T') {
							goto l151
						}
						position++
					}
				l156:
					{
						position158, tokenIndex158 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l159
						}
						position++
						goto l158
					l159:
						position, tokenIndex = position158, tokenIndex158
						if buffer[position] != rune('E') {
							goto l151
						}
						position++
					}
				l158:
					goto l134
				l151:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l160
					}
					position++
					if buffer[position] != rune('4') {
						goto l160
					}
					position++
					{
						position161, tokenIndex161 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l162
						}
						position++
						goto l161
					l162:
						position, tokenIndex = position161, tokenIndex161
						if buffer[position] != rune('B') {
							goto l160
						}
						position++
					}
				l161:
					{
						position163, tokenIndex163 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l164
						}
						position++
						goto l163
					l164:
						position, tokenIndex = position163, tokenIndex163
						if buffer[position] != rune('Y') {
							goto l160
						}
						position++
					}
				l163:
					{
						position165, tokenIndex165 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l166
						}
						position++
						goto l165
					l166:
						position, tokenIndex = position165, tokenIndex165
						if buffer[position] != rune('T') {
							goto l160
						}
						position++
					}
				l165:
					{
						position167, tokenIndex167 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l168
						}
						position++
						goto l167
					l168:
						position, tokenIndex = position167, tokenIndex167
						if buffer[position] != rune('E') {
							goto l160
						}
						position++
					}
				l167:
					goto l134
				l160:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l169
					}
					position++
					{
						position170, tokenIndex170 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l171
						}
						position++
						goto l170
					l171:
						position, tokenIndex = position170, tokenIndex170
						if buffer[position] != rune('Q') {
							goto l169
						}
						position++
					}
				l170:
					{
						position172, tokenIndex172 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l173
						}
						position++
						goto l172
					l173:
						position, tokenIndex = position172, tokenIndex172
						if buffer[position] != rune('U') {
							goto l169
						}
						position++
					}
				l172:
					{
						position174, tokenIndex174 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l175
						}
						position++
						goto l174
					l175:
						position, tokenIndex = position174, tokenIndex174
						if buffer[position] != rune('A') {
							goto l169
						}
						position++
					}
				l174:
					{
						position176, tokenIndex176 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l177
						}
						position++
						goto l176
					l177:
						position, tokenIndex = position176, tokenIndex176
						if buffer[position] != rune('D') {
							goto l169
						}
						position++
					}
				l176:
					goto l134
				l169:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l178
					}
					position++
					{
						position179, tokenIndex179 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l180
						}
						position++
						goto l179
					l180:
						position, tokenIndex = position179, tokenIndex179
						if buffer[position] != rune('T') {
							goto l178
						}
						position++
					}
				l179:
					{
						position181, tokenIndex181 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l182
						}
						position++
						goto l181
					l182:
						position, tokenIndex = position181, tokenIndex181
						if buffer[position] != rune('C') {
							goto l178
						}
						position++
					}
				l181:
					goto l134
				l178:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l183
					}
					position++
					{
						position184, tokenIndex184 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l185
						}
						position++
						goto l184
					l185:
						position, tokenIndex = position184, tokenIndex184
						if buffer[position] != rune('L') {
							goto l183
						}
						position++
					}
				l184:
					{
						position186, tokenIndex186 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l187
						}
						position++
						goto l186
					l187:
						position, tokenIndex = position186, tokenIndex186
						if buffer[position] != rune('O') {
							goto l183
						}
						position++
					}
				l186:
					{
						position188, tokenIndex188 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l189
						}
						position++
						goto l188
					l189:
						position, tokenIndex = position188, tokenIndex188
						if buffer[position] != rune('C') {
							goto l183
						}
						position++
					}
				l188:
					{
						position190, tokenIndex190 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l191
						}
						position++
						goto l190
					l191:
						position, tokenIndex = position190, tokenIndex190
						if buffer[position] != rune('A') {
							goto l183
						}
						position++
					}
				l190:
					{
						position192, tokenIndex192 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l193
						}
						position++
						goto l192
					l193:
						position, tokenIndex = position192, tokenIndex192
						if buffer[position] != rune('L') {
							goto l183
						}
						position++
					}
				l192:
					{
						position194, tokenIndex194 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l195
						}
						position++
						goto l194
					l195:
						position, tokenIndex = position194, tokenIndex194
						if buffer[position] != rune('E') {
							goto l183
						}
						position++
					}
				l194:
					{
						position196, tokenIndex196 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l197
						}
						position++
						goto l196
					l197:
						position, tokenIndex = position196, tokenIndex196
						if buffer[position] != rune('N') {
							goto l183
						}
						position++
					}
				l196:
					{
						position198, tokenIndex198 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l199
						}
						position++
						goto l198
					l199:
						position, tokenIndex = position198, tokenIndex198
						if buffer[position] != rune('T') {
							goto l183
						}
						position++
					}
				l198:
					{
						position200, tokenIndex200 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l201
						}
						position++
						goto l200
					l201:
						position, tokenIndex = position200, tokenIndex200
						if buffer[position] != rune('R') {
							goto l183
						}
						position++
					}
				l200:
					{
						position202, tokenIndex202 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l203
						}
						position++
						goto l202
					l203:
						position, tokenIndex = position202, tokenIndex202
						if buffer[position] != rune('Y') {
							goto l183
						}
						position++
					}
				l202:
					goto l134
				l183:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l204
					}
					position++
					{
						position205, tokenIndex205 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l206
						}
						position++
						goto l205
					l206:
						position, tokenIndex = position205, tokenIndex205
						if buffer[position] != rune('S') {
							goto l204
						}
						position++
					}
				l205:
					{
						position207, tokenIndex207 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex = position207, tokenIndex207
						if buffer[position] != rune('I') {
							goto l204
						}
						position++
					}
				l207:
					{
						position209, tokenIndex209 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l210
						}
						position++
						goto l209
					l210:
						position, tokenIndex = position209, tokenIndex209
						if buffer[position] != rune('Z') {
							goto l204
						}
						position++
					}
				l209:
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex = position211, tokenIndex211
						if buffer[position] != rune('E') {
							goto l204
						}
						position++
					}
				l211:
					goto l134
				l204:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l132
					}
					position++
					{
						position213, tokenIndex213 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l214
						}
						position++
						goto l213
					l214:
						position, tokenIndex = position213, tokenIndex213
						if buffer[position] != rune('T') {
							goto l132
						}
						position++
					}
				l213:
					{
						position215, tokenIndex215 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l216
						}
						position++
						goto l215
					l216:
						position, tokenIndex = position215, tokenIndex215
						if buffer[position] != rune('Y') {
							goto l132
						}
						position++
					}
				l215:
					{
						position217, tokenIndex217 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l218
						}
						position++
						goto l217
					l218:
						position, tokenIndex = position217, tokenIndex217
						if buffer[position] != rune('P') {
							goto l132
						}
						position++
					}
				l217:
					{
						position219, tokenIndex219 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l220
						}
						position++
						goto l219
					l220:
						position, tokenIndex = position219, tokenIndex219
						if buffer[position] != rune('E') {
							goto l132
						}
						position++
					}
				l219:
				}
			l134:
				add(ruleLabelContainingDirectiveName, position133)
			}
			return true
		l132:
			position, tokenIndex = position132, tokenIndex132
			return false
		},
		/* 12 SymbolArgs <- <(SymbolArg (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position221, tokenIndex221 := position, tokenIndex
			{
				position222 := position
				if !_rules[ruleSymbolArg]() {
					goto l221
				}
			l223:
				{
					position224, tokenIndex224 := position, tokenIndex
					{
						position225, tokenIndex225 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l225
						}
						goto l226
					l225:
						position, tokenIndex = position225, tokenIndex225
					}
				l226:
					if buffer[position] != rune(',') {
						goto l224
					}
					position++
					{
						position227, tokenIndex227 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l227
						}
						goto l228
					l227:
						position, tokenIndex = position227, tokenIndex227
					}
				l228:
					if !_rules[ruleSymbolArg]() {
						goto l224
					}
					goto l223
				l224:
					position, tokenIndex = position224, tokenIndex224
				}
				add(ruleSymbolArgs, position222)
			}
			return true
		l221:
			position, tokenIndex = position221, tokenIndex221
			return false
		},
		/* 13 SymbolArg <- <(Offset / SymbolType / ((Offset / LocalSymbol / SymbolName / Dot) WS? Operator WS? (Offset / LocalSymbol / SymbolName)) / (LocalSymbol TCMarker?) / (SymbolName Offset) / (SymbolName TCMarker?))> */
		func() bool {
			position229, tokenIndex229 := position, tokenIndex
			{
				position230 := position
				{
					position231, tokenIndex231 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l232
					}
					goto l231
				l232:
					position, tokenIndex = position231, tokenIndex231
					if !_rules[ruleSymbolType]() {
						goto l233
					}
					goto l231
				l233:
					position, tokenIndex = position231, tokenIndex231
					{
						position235, tokenIndex235 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l236
						}
						goto l235
					l236:
						position, tokenIndex = position235, tokenIndex235
						if !_rules[ruleLocalSymbol]() {
							goto l237
						}
						goto l235
					l237:
						position, tokenIndex = position235, tokenIndex235
						if !_rules[ruleSymbolName]() {
							goto l238
						}
						goto l235
					l238:
						position, tokenIndex = position235, tokenIndex235
						if !_rules[ruleDot]() {
							goto l234
						}
					}
				l235:
					{
						position239, tokenIndex239 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l239
						}
						goto l240
					l239:
						position, tokenIndex = position239, tokenIndex239
					}
				l240:
					if !_rules[ruleOperator]() {
						goto l234
					}
					{
						position241, tokenIndex241 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l241
						}
						goto l242
					l241:
						position, tokenIndex = position241, tokenIndex241
					}
				l242:
					{
						position243, tokenIndex243 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l244
						}
						goto l243
					l244:
						position, tokenIndex = position243, tokenIndex243
						if !_rules[ruleLocalSymbol]() {
							goto l245
						}
						goto l243
					l245:
						position, tokenIndex = position243, tokenIndex243
						if !_rules[ruleSymbolName]() {
							goto l234
						}
					}
				l243:
					goto l231
				l234:
					position, tokenIndex = position231, tokenIndex231
					if !_rules[ruleLocalSymbol]() {
						goto l246
					}
					{
						position247, tokenIndex247 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l247
						}
						goto l248
					l247:
						position, tokenIndex = position247, tokenIndex247
					}
				l248:
					goto l231
				l246:
					position, tokenIndex = position231, tokenIndex231
					if !_rules[ruleSymbolName]() {
						goto l249
					}
					if !_rules[ruleOffset]() {
						goto l249
					}
					goto l231
				l249:
					position, tokenIndex = position231, tokenIndex231
					if !_rules[ruleSymbolName]() {
						goto l229
					}
					{
						position250, tokenIndex250 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l250
						}
						goto l251
					l250:
						position, tokenIndex = position250, tokenIndex250
					}
				l251:
				}
			l231:
				add(ruleSymbolArg, position230)
			}
			return true
		l229:
			position, tokenIndex = position229, tokenIndex229
			return false
		},
		/* 14 SymbolType <- <(('@' 'f' 'u' 'n' 'c' 't' 'i' 'o' 'n') / ('@' 'o' 'b' 'j' 'e' 'c' 't'))> */
		func() bool {
			position252, tokenIndex252 := position, tokenIndex
			{
				position253 := position
				{
					position254, tokenIndex254 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l255
					}
					position++
					if buffer[position] != rune('f') {
						goto l255
					}
					position++
					if buffer[position] != rune('u') {
						goto l255
					}
					position++
					if buffer[position] != rune('n') {
						goto l255
					}
					position++
					if buffer[position] != rune('c') {
						goto l255
					}
					position++
					if buffer[position] != rune('t') {
						goto l255
					}
					position++
					if buffer[position] != rune('i') {
						goto l255
					}
					position++
					if buffer[position] != rune('o') {
						goto l255
					}
					position++
					if buffer[position] != rune('n') {
						goto l255
					}
					position++
					goto l254
				l255:
					position, tokenIndex = position254, tokenIndex254
					if buffer[position] != rune('@') {
						goto l252
					}
					position++
					if buffer[position] != rune('o') {
						goto l252
					}
					position++
					if buffer[position] != rune('b') {
						goto l252
					}
					position++
					if buffer[position] != rune('j') {
						goto l252
					}
					position++
					if buffer[position] != rune('e') {
						goto l252
					}
					position++
					if buffer[position] != rune('c') {
						goto l252
					}
					position++
					if buffer[position] != rune('t') {
						goto l252
					}
					position++
				}
			l254:
				add(ruleSymbolType, position253)
			}
			return true
		l252:
			position, tokenIndex = position252, tokenIndex252
			return false
		},
		/* 15 Dot <- <'.'> */
		func() bool {
			position256, tokenIndex256 := position, tokenIndex
			{
				position257 := position
				if buffer[position] != rune('.') {
					goto l256
				}
				position++
				add(ruleDot, position257)
			}
			return true
		l256:
			position, tokenIndex = position256, tokenIndex256
			return false
		},
		/* 16 TCMarker <- <('[' 'T' 'C' ']')> */
		func() bool {
			position258, tokenIndex258 := position, tokenIndex
			{
				position259 := position
				if buffer[position] != rune('[') {
					goto l258
				}
				position++
				if buffer[position] != rune('T') {
					goto l258
				}
				position++
				if buffer[position] != rune('C') {
					goto l258
				}
				position++
				if buffer[position] != rune(']') {
					goto l258
				}
				position++
				add(ruleTCMarker, position259)
			}
			return true
		l258:
			position, tokenIndex = position258, tokenIndex258
			return false
		},
		/* 17 EscapedChar <- <('\\' .)> */
		func() bool {
			position260, tokenIndex260 := position, tokenIndex
			{
				position261 := position
				if buffer[position] != rune('\\') {
					goto l260
				}
				position++
				if !matchDot() {
					goto l260
				}
				add(ruleEscapedChar, position261)
			}
			return true
		l260:
			position, tokenIndex = position260, tokenIndex260
			return false
		},
		/* 18 WS <- <(' ' / '\t')+> */
		func() bool {
			position262, tokenIndex262 := position, tokenIndex
			{
				position263 := position
				{
					position266, tokenIndex266 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l267
					}
					position++
					goto l266
				l267:
					position, tokenIndex = position266, tokenIndex266
					if buffer[position] != rune('\t') {
						goto l262
					}
					position++
				}
			l266:
			l264:
				{
					position265, tokenIndex265 := position, tokenIndex
					{
						position268, tokenIndex268 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l269
						}
						position++
						goto l268
					l269:
						position, tokenIndex = position268, tokenIndex268
						if buffer[position] != rune('\t') {
							goto l265
						}
						position++
					}
				l268:
					goto l264
				l265:
					position, tokenIndex = position265, tokenIndex265
				}
				add(ruleWS, position263)
			}
			return true
		l262:
			position, tokenIndex = position262, tokenIndex262
			return false
		},
		/* 19 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position270, tokenIndex270 := position, tokenIndex
			{
				position271 := position
				if buffer[position] != rune('#') {
					goto l270
				}
				position++
			l272:
				{
					position273, tokenIndex273 := position, tokenIndex
					{
						position274, tokenIndex274 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l274
						}
						position++
						goto l273
					l274:
						position, tokenIndex = position274, tokenIndex274
					}
					if !matchDot() {
						goto l273
					}
					goto l272
				l273:
					position, tokenIndex = position273, tokenIndex273
				}
				add(ruleComment, position271)
			}
			return true
		l270:
			position, tokenIndex = position270, tokenIndex270
			return false
		},
		/* 20 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position275, tokenIndex275 := position, tokenIndex
			{
				position276 := position
				{
					position277, tokenIndex277 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l278
					}
					goto l277
				l278:
					position, tokenIndex = position277, tokenIndex277
					if !_rules[ruleLocalLabel]() {
						goto l279
					}
					goto l277
				l279:
					position, tokenIndex = position277, tokenIndex277
					if !_rules[ruleSymbolName]() {
						goto l275
					}
				}
			l277:
				if buffer[position] != rune(':') {
					goto l275
				}
				position++
				add(ruleLabel, position276)
			}
			return true
		l275:
			position, tokenIndex = position275, tokenIndex275
			return false
		},
		/* 21 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position280, tokenIndex280 := position, tokenIndex
			{
				position281 := position
				{
					position282, tokenIndex282 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l283
					}
					position++
					goto l282
				l283:
					position, tokenIndex = position282, tokenIndex282
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l284
					}
					position++
					goto l282
				l284:
					position, tokenIndex = position282, tokenIndex282
					if buffer[position] != rune('.') {
						goto l285
					}
					position++
					goto l282
				l285:
					position, tokenIndex = position282, tokenIndex282
					if buffer[position] != rune('_') {
						goto l280
					}
					position++
				}
			l282:
			l286:
				{
					position287, tokenIndex287 := position, tokenIndex
					{
						position288, tokenIndex288 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l289
						}
						position++
						goto l288
					l289:
						position, tokenIndex = position288, tokenIndex288
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l290
						}
						position++
						goto l288
					l290:
						position, tokenIndex = position288, tokenIndex288
						if buffer[position] != rune('.') {
							goto l291
						}
						position++
						goto l288
					l291:
						position, tokenIndex = position288, tokenIndex288
						{
							position293, tokenIndex293 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l294
							}
							position++
							goto l293
						l294:
							position, tokenIndex = position293, tokenIndex293
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l292
							}
							position++
						}
					l293:
						goto l288
					l292:
						position, tokenIndex = position288, tokenIndex288
						if buffer[position] != rune('$') {
							goto l295
						}
						position++
						goto l288
					l295:
						position, tokenIndex = position288, tokenIndex288
						if buffer[position] != rune('_') {
							goto l287
						}
						position++
					}
				l288:
					goto l286
				l287:
					position, tokenIndex = position287, tokenIndex287
				}
				add(ruleSymbolName, position281)
			}
			return true
		l280:
			position, tokenIndex = position280, tokenIndex280
			return false
		},
		/* 22 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position296, tokenIndex296 := position, tokenIndex
			{
				position297 := position
				if buffer[position] != rune('.') {
					goto l296
				}
				position++
				if buffer[position] != rune('L') {
					goto l296
				}
				position++
				{
					position300, tokenIndex300 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l301
					}
					position++
					goto l300
				l301:
					position, tokenIndex = position300, tokenIndex300
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l302
					}
					position++
					goto l300
				l302:
					position, tokenIndex = position300, tokenIndex300
					if buffer[position] != rune('.') {
						goto l303
					}
					position++
					goto l300
				l303:
					position, tokenIndex = position300, tokenIndex300
					{
						position305, tokenIndex305 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l306
						}
						position++
						goto l305
					l306:
						position, tokenIndex = position305, tokenIndex305
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l304
						}
						position++
					}
				l305:
					goto l300
				l304:
					position, tokenIndex = position300, tokenIndex300
					if buffer[position] != rune('$') {
						goto l307
					}
					position++
					goto l300
				l307:
					position, tokenIndex = position300, tokenIndex300
					if buffer[position] != rune('_') {
						goto l296
					}
					position++
				}
			l300:
			l298:
				{
					position299, tokenIndex299 := position, tokenIndex
					{
						position308, tokenIndex308 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l309
						}
						position++
						goto l308
					l309:
						position, tokenIndex = position308, tokenIndex308
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l310
						}
						position++
						goto l308
					l310:
						position, tokenIndex = position308, tokenIndex308
						if buffer[position] != rune('.') {
							goto l311
						}
						position++
						goto l308
					l311:
						position, tokenIndex = position308, tokenIndex308
						{
							position313, tokenIndex313 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l314
							}
							position++
							goto l313
						l314:
							position, tokenIndex = position313, tokenIndex313
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l312
							}
							position++
						}
					l313:
						goto l308
					l312:
						position, tokenIndex = position308, tokenIndex308
						if buffer[position] != rune('$') {
							goto l315
						}
						position++
						goto l308
					l315:
						position, tokenIndex = position308, tokenIndex308
						if buffer[position] != rune('_') {
							goto l299
						}
						position++
					}
				l308:
					goto l298
				l299:
					position, tokenIndex = position299, tokenIndex299
				}
				add(ruleLocalSymbol, position297)
			}
			return true
		l296:
			position, tokenIndex = position296, tokenIndex296
			return false
		},
		/* 23 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position316, tokenIndex316 := position, tokenIndex
			{
				position317 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l316
				}
				position++
			l318:
				{
					position319, tokenIndex319 := position, tokenIndex
					{
						position320, tokenIndex320 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l321
						}
						position++
						goto l320
					l321:
						position, tokenIndex = position320, tokenIndex320
						if buffer[position] != rune('$') {
							goto l319
						}
						position++
					}
				l320:
					goto l318
				l319:
					position, tokenIndex = position319, tokenIndex319
				}
				add(ruleLocalLabel, position317)
			}
			return true
		l316:
			position, tokenIndex = position316, tokenIndex316
			return false
		},
		/* 24 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position322, tokenIndex322 := position, tokenIndex
			{
				position323 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l322
				}
				position++
			l324:
				{
					position325, tokenIndex325 := position, tokenIndex
					{
						position326, tokenIndex326 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l327
						}
						position++
						goto l326
					l327:
						position, tokenIndex = position326, tokenIndex326
						if buffer[position] != rune('$') {
							goto l325
						}
						position++
					}
				l326:
					goto l324
				l325:
					position, tokenIndex = position325, tokenIndex325
				}
				{
					position328, tokenIndex328 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l329
					}
					position++
					goto l328
				l329:
					position, tokenIndex = position328, tokenIndex328
					if buffer[position] != rune('f') {
						goto l322
					}
					position++
				}
			l328:
				add(ruleLocalLabelRef, position323)
			}
			return true
		l322:
			position, tokenIndex = position322, tokenIndex322
			return false
		},
		/* 25 Instruction <- <(InstructionName (WS InstructionArg (WS? ',' WS? InstructionArg)*)? (WS? '{' InstructionArg '}')*)> */
		func() bool {
			position330, tokenIndex330 := position, tokenIndex
			{
				position331 := position
				if !_rules[ruleInstructionName]() {
					goto l330
				}
				{
					position332, tokenIndex332 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l332
					}
					if !_rules[ruleInstructionArg]() {
						goto l332
					}
				l334:
					{
						position335, tokenIndex335 := position, tokenIndex
						{
							position336, tokenIndex336 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l336
							}
							goto l337
						l336:
							position, tokenIndex = position336, tokenIndex336
						}
					l337:
						if buffer[position] != rune(',') {
							goto l335
						}
						position++
						{
							position338, tokenIndex338 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l338
							}
							goto l339
						l338:
							position, tokenIndex = position338, tokenIndex338
						}
					l339:
						if !_rules[ruleInstructionArg]() {
							goto l335
						}
						goto l334
					l335:
						position, tokenIndex = position335, tokenIndex335
					}
					goto l333
				l332:
					position, tokenIndex = position332, tokenIndex332
				}
			l333:
			l340:
				{
					position341, tokenIndex341 := position, tokenIndex
					{
						position342, tokenIndex342 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l342
						}
						goto l343
					l342:
						position, tokenIndex = position342, tokenIndex342
					}
				l343:
					if buffer[position] != rune('{') {
						goto l341
					}
					position++
					if !_rules[ruleInstructionArg]() {
						goto l341
					}
					if buffer[position] != rune('}') {
						goto l341
					}
					position++
					goto l340
				l341:
					position, tokenIndex = position341, tokenIndex341
				}
				add(ruleInstruction, position331)
			}
			return true
		l330:
			position, tokenIndex = position330, tokenIndex330
			return false
		},
		/* 26 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position344, tokenIndex344 := position, tokenIndex
			{
				position345 := position
				{
					position346, tokenIndex346 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l347
					}
					position++
					goto l346
				l347:
					position, tokenIndex = position346, tokenIndex346
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l344
					}
					position++
				}
			l346:
			l348:
				{
					position349, tokenIndex349 := position, tokenIndex
					{
						position350, tokenIndex350 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l351
						}
						position++
						goto l350
					l351:
						position, tokenIndex = position350, tokenIndex350
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l352
						}
						position++
						goto l350
					l352:
						position, tokenIndex = position350, tokenIndex350
						{
							position353, tokenIndex353 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l354
							}
							position++
							goto l353
						l354:
							position, tokenIndex = position353, tokenIndex353
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l349
							}
							position++
						}
					l353:
					}
				l350:
					goto l348
				l349:
					position, tokenIndex = position349, tokenIndex349
				}
				{
					position355, tokenIndex355 := position, tokenIndex
					{
						position357, tokenIndex357 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l358
						}
						position++
						goto l357
					l358:
						position, tokenIndex = position357, tokenIndex357
						if buffer[position] != rune('+') {
							goto l359
						}
						position++
						goto l357
					l359:
						position, tokenIndex = position357, tokenIndex357
						if buffer[position] != rune('-') {
							goto l355
						}
						position++
					}
				l357:
					goto l356
				l355:
					position, tokenIndex = position355, tokenIndex355
				}
			l356:
				add(ruleInstructionName, position345)
			}
			return true
		l344:
			position, tokenIndex = position344, tokenIndex344
			return false
		},
		/* 27 InstructionArg <- <(IndirectionIndicator? (RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / MemoryRef))> */
		func() bool {
			position360, tokenIndex360 := position, tokenIndex
			{
				position361 := position
				{
					position362, tokenIndex362 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l362
					}
					goto l363
				l362:
					position, tokenIndex = position362, tokenIndex362
				}
			l363:
				{
					position364, tokenIndex364 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l365
					}
					goto l364
				l365:
					position, tokenIndex = position364, tokenIndex364
					if !_rules[ruleLocalLabelRef]() {
						goto l366
					}
					goto l364
				l366:
					position, tokenIndex = position364, tokenIndex364
					if !_rules[ruleTOCRefHigh]() {
						goto l367
					}
					goto l364
				l367:
					position, tokenIndex = position364, tokenIndex364
					if !_rules[ruleTOCRefLow]() {
						goto l368
					}
					goto l364
				l368:
					position, tokenIndex = position364, tokenIndex364
					if !_rules[ruleMemoryRef]() {
						goto l360
					}
				}
			l364:
				add(ruleInstructionArg, position361)
			}
			return true
		l360:
			position, tokenIndex = position360, tokenIndex360
			return false
		},
		/* 28 TOCRefHigh <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('h' / 'H') ('a' / 'A')))> */
		func() bool {
			position369, tokenIndex369 := position, tokenIndex
			{
				position370 := position
				if buffer[position] != rune('.') {
					goto l369
				}
				position++
				if buffer[position] != rune('T') {
					goto l369
				}
				position++
				if buffer[position] != rune('O') {
					goto l369
				}
				position++
				if buffer[position] != rune('C') {
					goto l369
				}
				position++
				if buffer[position] != rune('.') {
					goto l369
				}
				position++
				if buffer[position] != rune('-') {
					goto l369
				}
				position++
				{
					position371, tokenIndex371 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l372
					}
					position++
					if buffer[position] != rune('b') {
						goto l372
					}
					position++
					goto l371
				l372:
					position, tokenIndex = position371, tokenIndex371
					if buffer[position] != rune('.') {
						goto l369
					}
					position++
					if buffer[position] != rune('L') {
						goto l369
					}
					position++
					{
						position375, tokenIndex375 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l376
						}
						position++
						goto l375
					l376:
						position, tokenIndex = position375, tokenIndex375
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l377
						}
						position++
						goto l375
					l377:
						position, tokenIndex = position375, tokenIndex375
						if buffer[position] != rune('_') {
							goto l378
						}
						position++
						goto l375
					l378:
						position, tokenIndex = position375, tokenIndex375
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l369
						}
						position++
					}
				l375:
				l373:
					{
						position374, tokenIndex374 := position, tokenIndex
						{
							position379, tokenIndex379 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l380
							}
							position++
							goto l379
						l380:
							position, tokenIndex = position379, tokenIndex379
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l381
							}
							position++
							goto l379
						l381:
							position, tokenIndex = position379, tokenIndex379
							if buffer[position] != rune('_') {
								goto l382
							}
							position++
							goto l379
						l382:
							position, tokenIndex = position379, tokenIndex379
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l374
							}
							position++
						}
					l379:
						goto l373
					l374:
						position, tokenIndex = position374, tokenIndex374
					}
				}
			l371:
				if buffer[position] != rune('@') {
					goto l369
				}
				position++
				{
					position383, tokenIndex383 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l384
					}
					position++
					goto l383
				l384:
					position, tokenIndex = position383, tokenIndex383
					if buffer[position] != rune('H') {
						goto l369
					}
					position++
				}
			l383:
				{
					position385, tokenIndex385 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l386
					}
					position++
					goto l385
				l386:
					position, tokenIndex = position385, tokenIndex385
					if buffer[position] != rune('A') {
						goto l369
					}
					position++
				}
			l385:
				add(ruleTOCRefHigh, position370)
			}
			return true
		l369:
			position, tokenIndex = position369, tokenIndex369
			return false
		},
		/* 29 TOCRefLow <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('l' / 'L')))> */
		func() bool {
			position387, tokenIndex387 := position, tokenIndex
			{
				position388 := position
				if buffer[position] != rune('.') {
					goto l387
				}
				position++
				if buffer[position] != rune('T') {
					goto l387
				}
				position++
				if buffer[position] != rune('O') {
					goto l387
				}
				position++
				if buffer[position] != rune('C') {
					goto l387
				}
				position++
				if buffer[position] != rune('.') {
					goto l387
				}
				position++
				if buffer[position] != rune('-') {
					goto l387
				}
				position++
				{
					position389, tokenIndex389 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l390
					}
					position++
					if buffer[position] != rune('b') {
						goto l390
					}
					position++
					goto l389
				l390:
					position, tokenIndex = position389, tokenIndex389
					if buffer[position] != rune('.') {
						goto l387
					}
					position++
					if buffer[position] != rune('L') {
						goto l387
					}
					position++
					{
						position393, tokenIndex393 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l394
						}
						position++
						goto l393
					l394:
						position, tokenIndex = position393, tokenIndex393
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l395
						}
						position++
						goto l393
					l395:
						position, tokenIndex = position393, tokenIndex393
						if buffer[position] != rune('_') {
							goto l396
						}
						position++
						goto l393
					l396:
						position, tokenIndex = position393, tokenIndex393
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l387
						}
						position++
					}
				l393:
				l391:
					{
						position392, tokenIndex392 := position, tokenIndex
						{
							position397, tokenIndex397 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l398
							}
							position++
							goto l397
						l398:
							position, tokenIndex = position397, tokenIndex397
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l399
							}
							position++
							goto l397
						l399:
							position, tokenIndex = position397, tokenIndex397
							if buffer[position] != rune('_') {
								goto l400
							}
							position++
							goto l397
						l400:
							position, tokenIndex = position397, tokenIndex397
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l392
							}
							position++
						}
					l397:
						goto l391
					l392:
						position, tokenIndex = position392, tokenIndex392
					}
				}
			l389:
				if buffer[position] != rune('@') {
					goto l387
				}
				position++
				{
					position401, tokenIndex401 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l402
					}
					position++
					goto l401
				l402:
					position, tokenIndex = position401, tokenIndex401
					if buffer[position] != rune('L') {
						goto l387
					}
					position++
				}
			l401:
				add(ruleTOCRefLow, position388)
			}
			return true
		l387:
			position, tokenIndex = position387, tokenIndex387
			return false
		},
		/* 30 IndirectionIndicator <- <'*'> */
		func() bool {
			position403, tokenIndex403 := position, tokenIndex
			{
				position404 := position
				if buffer[position] != rune('*') {
					goto l403
				}
				position++
				add(ruleIndirectionIndicator, position404)
			}
			return true
		l403:
			position, tokenIndex = position403, tokenIndex403
			return false
		},
		/* 31 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset))) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position405, tokenIndex405 := position, tokenIndex
			{
				position406 := position
				{
					position407, tokenIndex407 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l408
					}
					position++
					{
						position409, tokenIndex409 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l410
						}
						position++
						goto l409
					l410:
						position, tokenIndex = position409, tokenIndex409
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l408
						}
						position++
					}
				l409:
				l411:
					{
						position412, tokenIndex412 := position, tokenIndex
						{
							position413, tokenIndex413 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l414
							}
							position++
							goto l413
						l414:
							position, tokenIndex = position413, tokenIndex413
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l415
							}
							position++
							goto l413
						l415:
							position, tokenIndex = position413, tokenIndex413
							{
								position416, tokenIndex416 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l417
								}
								position++
								goto l416
							l417:
								position, tokenIndex = position416, tokenIndex416
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l412
								}
								position++
							}
						l416:
						}
					l413:
						goto l411
					l412:
						position, tokenIndex = position412, tokenIndex412
					}
					goto l407
				l408:
					position, tokenIndex = position407, tokenIndex407
					{
						position418, tokenIndex418 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l418
						}
						position++
						goto l419
					l418:
						position, tokenIndex = position418, tokenIndex418
					}
				l419:
					{
						position420, tokenIndex420 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l421
						}
						if !_rules[ruleOffset]() {
							goto l421
						}
						goto l420
					l421:
						position, tokenIndex = position420, tokenIndex420
						if !_rules[ruleOffset]() {
							goto l405
						}
					}
				l420:
				}
			l407:
				{
					position422, tokenIndex422 := position, tokenIndex
					{
						position423, tokenIndex423 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l424
						}
						position++
						goto l423
					l424:
						position, tokenIndex = position423, tokenIndex423
						if buffer[position] != rune('b') {
							goto l425
						}
						position++
						goto l423
					l425:
						position, tokenIndex = position423, tokenIndex423
						if buffer[position] != rune(':') {
							goto l426
						}
						position++
						goto l423
					l426:
						position, tokenIndex = position423, tokenIndex423
						if buffer[position] != rune('(') {
							goto l427
						}
						position++
						goto l423
					l427:
						position, tokenIndex = position423, tokenIndex423
						if buffer[position] != rune('+') {
							goto l428
						}
						position++
						goto l423
					l428:
						position, tokenIndex = position423, tokenIndex423
						if buffer[position] != rune('-') {
							goto l422
						}
						position++
					}
				l423:
					goto l405
				l422:
					position, tokenIndex = position422, tokenIndex422
				}
				add(ruleRegisterOrConstant, position406)
			}
			return true
		l405:
			position, tokenIndex = position405, tokenIndex405
			return false
		},
		/* 32 MemoryRef <- <((SymbolRef BaseIndexScale) / SymbolRef / (Offset* BaseIndexScale) / (SegmentRegister Offset BaseIndexScale) / (SegmentRegister BaseIndexScale) / (SegmentRegister Offset) / BaseIndexScale)> */
		func() bool {
			position429, tokenIndex429 := position, tokenIndex
			{
				position430 := position
				{
					position431, tokenIndex431 := position, tokenIndex
					if !_rules[ruleSymbolRef]() {
						goto l432
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l432
					}
					goto l431
				l432:
					position, tokenIndex = position431, tokenIndex431
					if !_rules[ruleSymbolRef]() {
						goto l433
					}
					goto l431
				l433:
					position, tokenIndex = position431, tokenIndex431
				l435:
					{
						position436, tokenIndex436 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l436
						}
						goto l435
					l436:
						position, tokenIndex = position436, tokenIndex436
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l434
					}
					goto l431
				l434:
					position, tokenIndex = position431, tokenIndex431
					if !_rules[ruleSegmentRegister]() {
						goto l437
					}
					if !_rules[ruleOffset]() {
						goto l437
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l437
					}
					goto l431
				l437:
					position, tokenIndex = position431, tokenIndex431
					if !_rules[ruleSegmentRegister]() {
						goto l438
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l438
					}
					goto l431
				l438:
					position, tokenIndex = position431, tokenIndex431
					if !_rules[ruleSegmentRegister]() {
						goto l439
					}
					if !_rules[ruleOffset]() {
						goto l439
					}
					goto l431
				l439:
					position, tokenIndex = position431, tokenIndex431
					if !_rules[ruleBaseIndexScale]() {
						goto l429
					}
				}
			l431:
				add(ruleMemoryRef, position430)
			}
			return true
		l429:
			position, tokenIndex = position429, tokenIndex429
			return false
		},
		/* 33 SymbolRef <- <((Offset* '+')? (LocalSymbol / SymbolName) Offset* ('@' Section Offset*)?)> */
		func() bool {
			position440, tokenIndex440 := position, tokenIndex
			{
				position441 := position
				{
					position442, tokenIndex442 := position, tokenIndex
				l444:
					{
						position445, tokenIndex445 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l445
						}
						goto l444
					l445:
						position, tokenIndex = position445, tokenIndex445
					}
					if buffer[position] != rune('+') {
						goto l442
					}
					position++
					goto l443
				l442:
					position, tokenIndex = position442, tokenIndex442
				}
			l443:
				{
					position446, tokenIndex446 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l447
					}
					goto l446
				l447:
					position, tokenIndex = position446, tokenIndex446
					if !_rules[ruleSymbolName]() {
						goto l440
					}
				}
			l446:
			l448:
				{
					position449, tokenIndex449 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l449
					}
					goto l448
				l449:
					position, tokenIndex = position449, tokenIndex449
				}
				{
					position450, tokenIndex450 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l450
					}
					position++
					if !_rules[ruleSection]() {
						goto l450
					}
				l452:
					{
						position453, tokenIndex453 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l453
						}
						goto l452
					l453:
						position, tokenIndex = position453, tokenIndex453
					}
					goto l451
				l450:
					position, tokenIndex = position450, tokenIndex450
				}
			l451:
				add(ruleSymbolRef, position441)
			}
			return true
		l440:
			position, tokenIndex = position440, tokenIndex440
			return false
		},
		/* 34 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position454, tokenIndex454 := position, tokenIndex
			{
				position455 := position
				if buffer[position] != rune('(') {
					goto l454
				}
				position++
				{
					position456, tokenIndex456 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l456
					}
					goto l457
				l456:
					position, tokenIndex = position456, tokenIndex456
				}
			l457:
				{
					position458, tokenIndex458 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l458
					}
					goto l459
				l458:
					position, tokenIndex = position458, tokenIndex458
				}
			l459:
				{
					position460, tokenIndex460 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l460
					}
					position++
					{
						position462, tokenIndex462 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l462
						}
						goto l463
					l462:
						position, tokenIndex = position462, tokenIndex462
					}
				l463:
					if !_rules[ruleRegisterOrConstant]() {
						goto l460
					}
					{
						position464, tokenIndex464 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l464
						}
						goto l465
					l464:
						position, tokenIndex = position464, tokenIndex464
					}
				l465:
					{
						position466, tokenIndex466 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l466
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l466
						}
						position++
					l468:
						{
							position469, tokenIndex469 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l469
							}
							position++
							goto l468
						l469:
							position, tokenIndex = position469, tokenIndex469
						}
						goto l467
					l466:
						position, tokenIndex = position466, tokenIndex466
					}
				l467:
					goto l461
				l460:
					position, tokenIndex = position460, tokenIndex460
				}
			l461:
				if buffer[position] != rune(')') {
					goto l454
				}
				position++
				add(ruleBaseIndexScale, position455)
			}
			return true
		l454:
			position, tokenIndex = position454, tokenIndex454
			return false
		},
		/* 35 Operator <- <('+' / '-')> */
		func() bool {
			position470, tokenIndex470 := position, tokenIndex
			{
				position471 := position
				{
					position472, tokenIndex472 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l473
					}
					position++
					goto l472
				l473:
					position, tokenIndex = position472, tokenIndex472
					if buffer[position] != rune('-') {
						goto l470
					}
					position++
				}
			l472:
				add(ruleOperator, position471)
			}
			return true
		l470:
			position, tokenIndex = position470, tokenIndex470
			return false
		},
		/* 36 Offset <- <('+'? '-'? (('0' ('b' / 'B') ('0' / '1')+) / ('0' ('x' / 'X') ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position474, tokenIndex474 := position, tokenIndex
			{
				position475 := position
				{
					position476, tokenIndex476 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l476
					}
					position++
					goto l477
				l476:
					position, tokenIndex = position476, tokenIndex476
				}
			l477:
				{
					position478, tokenIndex478 := position, tokenIndex
					if buffer[position] != rune('-') {
						goto l478
					}
					position++
					goto l479
				l478:
					position, tokenIndex = position478, tokenIndex478
				}
			l479:
				{
					position480, tokenIndex480 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l481
					}
					position++
					{
						position482, tokenIndex482 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l483
						}
						position++
						goto l482
					l483:
						position, tokenIndex = position482, tokenIndex482
						if buffer[position] != rune('B') {
							goto l481
						}
						position++
					}
				l482:
					{
						position486, tokenIndex486 := position, tokenIndex
						if buffer[position] != rune('0') {
							goto l487
						}
						position++
						goto l486
					l487:
						position, tokenIndex = position486, tokenIndex486
						if buffer[position] != rune('1') {
							goto l481
						}
						position++
					}
				l486:
				l484:
					{
						position485, tokenIndex485 := position, tokenIndex
						{
							position488, tokenIndex488 := position, tokenIndex
							if buffer[position] != rune('0') {
								goto l489
							}
							position++
							goto l488
						l489:
							position, tokenIndex = position488, tokenIndex488
							if buffer[position] != rune('1') {
								goto l485
							}
							position++
						}
					l488:
						goto l484
					l485:
						position, tokenIndex = position485, tokenIndex485
					}
					goto l480
				l481:
					position, tokenIndex = position480, tokenIndex480
					if buffer[position] != rune('0') {
						goto l490
					}
					position++
					{
						position491, tokenIndex491 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l492
						}
						position++
						goto l491
					l492:
						position, tokenIndex = position491, tokenIndex491
						if buffer[position] != rune('X') {
							goto l490
						}
						position++
					}
				l491:
					{
						position495, tokenIndex495 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l496
						}
						position++
						goto l495
					l496:
						position, tokenIndex = position495, tokenIndex495
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l497
						}
						position++
						goto l495
					l497:
						position, tokenIndex = position495, tokenIndex495
						{
							position498, tokenIndex498 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l499
							}
							position++
							goto l498
						l499:
							position, tokenIndex = position498, tokenIndex498
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l490
							}
							position++
						}
					l498:
					}
				l495:
				l493:
					{
						position494, tokenIndex494 := position, tokenIndex
						{
							position500, tokenIndex500 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l501
							}
							position++
							goto l500
						l501:
							position, tokenIndex = position500, tokenIndex500
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l502
							}
							position++
							goto l500
						l502:
							position, tokenIndex = position500, tokenIndex500
							{
								position503, tokenIndex503 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l504
								}
								position++
								goto l503
							l504:
								position, tokenIndex = position503, tokenIndex503
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l494
								}
								position++
							}
						l503:
						}
					l500:
						goto l493
					l494:
						position, tokenIndex = position494, tokenIndex494
					}
					goto l480
				l490:
					position, tokenIndex = position480, tokenIndex480
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l474
					}
					position++
				l505:
					{
						position506, tokenIndex506 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l506
						}
						position++
						goto l505
					l506:
						position, tokenIndex = position506, tokenIndex506
					}
				}
			l480:
				add(ruleOffset, position475)
			}
			return true
		l474:
			position, tokenIndex = position474, tokenIndex474
			return false
		},
		/* 37 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position507, tokenIndex507 := position, tokenIndex
			{
				position508 := position
				{
					position511, tokenIndex511 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l512
					}
					position++
					goto l511
				l512:
					position, tokenIndex = position511, tokenIndex511
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l513
					}
					position++
					goto l511
				l513:
					position, tokenIndex = position511, tokenIndex511
					if buffer[position] != rune('@') {
						goto l507
					}
					position++
				}
			l511:
			l509:
				{
					position510, tokenIndex510 := position, tokenIndex
					{
						position514, tokenIndex514 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l515
						}
						position++
						goto l514
					l515:
						position, tokenIndex = position514, tokenIndex514
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l516
						}
						position++
						goto l514
					l516:
						position, tokenIndex = position514, tokenIndex514
						if buffer[position] != rune('@') {
							goto l510
						}
						position++
					}
				l514:
					goto l509
				l510:
					position, tokenIndex = position510, tokenIndex510
				}
				add(ruleSection, position508)
			}
			return true
		l507:
			position, tokenIndex = position507, tokenIndex507
			return false
		},
		/* 38 SegmentRegister <- <('%' ([c-g] / 's') ('s' ':'))> */
		func() bool {
			position517, tokenIndex517 := position, tokenIndex
			{
				position518 := position
				if buffer[position] != rune('%') {
					goto l517
				}
				position++
				{
					position519, tokenIndex519 := position, tokenIndex
					if c := buffer[position]; c < rune('c') || c > rune('g') {
						goto l520
					}
					position++
					goto l519
				l520:
					position, tokenIndex = position519, tokenIndex519
					if buffer[position] != rune('s') {
						goto l517
					}
					position++
				}
			l519:
				if buffer[position] != rune('s') {
					goto l517
				}
				position++
				if buffer[position] != rune(':') {
					goto l517
				}
				position++
				add(ruleSegmentRegister, position518)
			}
			return true
		l517:
			position, tokenIndex = position517, tokenIndex517
			return false
		},
	}
	p.rules = _rules
}
