package normalize

import (
	"fmt"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Output budget: the normalized document may hold at most outputBudgetFactor × input size +
// outputBudgetSlack bytes of text. Parsers copy shared input text (a rule description, an
// advisory, a document author) into many items; without this bound a crafted document of a few
// MiB could expand into gigabytes downstream (store rows, API responses).
const (
	outputBudgetFactor = 4
	outputBudgetSlack  = 1 << 20
	// itemOverhead approximates the fixed cost of one item or list element in the budget.
	itemOverhead = 16
)

// builder accumulates a Document while enforcing item-count and output-size limits.
type builder struct {
	doc      *evidence.Document
	maxItems int
	budget   int64
	compIdx  map[string]int // PURL -> index in doc.Components
}

func newBuilder(format evidence.Format, inputLen int, opts Options) *builder {
	return &builder{
		doc:      &evidence.Document{Format: format},
		maxItems: opts.MaxItems,
		budget:   int64(inputLen)*outputBudgetFactor + outputBudgetSlack,
		compIdx:  map[string]int{},
	}
}

func (b *builder) spend(n int) error {
	b.budget -= int64(n)
	if b.budget < 0 {
		return fmt.Errorf("%w: normalized output is too large relative to the input", ErrLimitExceeded)
	}
	return nil
}

// addComponent appends c, merging it into an earlier component with the same PURL (licenses are
// unioned, Direct is OR-ed). Components without a PURL are ignored by callers.
func (b *builder) addComponent(c evidence.Component) error {
	if i, ok := b.compIdx[c.PURL]; ok {
		prev := &b.doc.Components[i]
		before := len(prev.Licenses)
		prev.Licenses = appendUnique(prev.Licenses, c.Licenses...)
		prev.Direct = prev.Direct || c.Direct
		return b.spend(itemOverhead * (len(prev.Licenses) - before))
	}
	if len(b.doc.Components) >= b.maxItems {
		return fmt.Errorf("%w: more than %d components", ErrLimitExceeded, b.maxItems)
	}
	if err := b.spend(componentSize(&c)); err != nil {
		return err
	}
	b.compIdx[c.PURL] = len(b.doc.Components)
	b.doc.Components = append(b.doc.Components, c)
	return nil
}

func (b *builder) addFinding(f evidence.Finding) error {
	if len(b.doc.Findings) >= b.maxItems {
		return fmt.Errorf("%w: more than %d findings", ErrLimitExceeded, b.maxItems)
	}
	if err := b.spend(findingSize(&f)); err != nil {
		return err
	}
	b.doc.Findings = append(b.doc.Findings, f)
	return nil
}

func (b *builder) addVEX(v evidence.VEXStatement) error {
	if len(b.doc.VEX) >= b.maxItems {
		return fmt.Errorf("%w: more than %d VEX statements", ErrLimitExceeded, b.maxItems)
	}
	n := itemOverhead + len(v.VulnID) + len(v.Justification) + len(v.ImpactStatement) + len(v.Author)
	n += stringsSize(v.Products)
	if err := b.spend(n); err != nil {
		return err
	}
	b.doc.VEX = append(b.doc.VEX, v)
	return nil
}

func stringsSize(ss []string) int {
	n := 0
	for _, s := range ss {
		n += itemOverhead + len(s)
	}
	return n
}

func componentSize(c *evidence.Component) int {
	return itemOverhead + len(c.PURL) + len(c.Name) + len(c.Version) + len(c.Ecosystem) +
		stringsSize(c.Licenses)
}

func findingSize(f *evidence.Finding) int {
	n := itemOverhead + len(f.Fingerprint) + len(f.Title) + len(f.Message) + len(f.RuleID) +
		stringsSize(f.FixedVersions)
	for _, t := range f.Tools {
		n += itemOverhead + len(t.Name) + len(t.Version)
	}
	if v := f.Vulnerability; v != nil {
		n += itemOverhead + len(v.ID) + len(v.Summary) + stringsSize(v.Aliases) + stringsSize(v.CWEs)
		for _, c := range v.CVSS {
			n += itemOverhead + len(c.Version) + len(c.Vector)
		}
	}
	if c := f.Component; c != nil {
		n += componentSize(c)
	}
	if l := f.Location; l != nil {
		n += itemOverhead + len(l.Path)
	}
	return n
}
