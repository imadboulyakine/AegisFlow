package normalize

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/imadboulyakine/aegisflow/internal/evidence"
)

// Default limits applied when the corresponding Options field is zero or negative.
const (
	// DefaultMaxBytes is the largest evidence document Parse accepts (64 MiB).
	DefaultMaxBytes int64 = 64 << 20
	// DefaultMaxItems bounds, separately, the number of components, findings and VEX statements
	// in one normalized document.
	DefaultMaxItems = 100_000
	// DefaultMaxDepth bounds JSON nesting (objects and arrays). Real tool output stays far below.
	DefaultMaxDepth = 64
)

// Sentinel errors. Parse and Detect wrap them with context; test with errors.Is.
var (
	// ErrUnknownFormat means the content does not look like any supported evidence format.
	ErrUnknownFormat = errors.New("unknown evidence format")
	// ErrUnsupportedVersion means the format was recognized but its version is not supported.
	ErrUnsupportedVersion = errors.New("unsupported evidence format version")
	// ErrTooLarge means the raw input exceeds Options.MaxBytes.
	ErrTooLarge = errors.New("evidence exceeds the size limit")
	// ErrLimitExceeded means the input exceeds a structural limit (nesting depth, item count,
	// normalized output budget).
	ErrLimitExceeded = errors.New("evidence exceeds a normalization limit")
	// ErrInvalid means the input is malformed JSON or violates the format's required structure.
	ErrInvalid = errors.New("invalid evidence document")
)

// Options tunes Parse. The zero value applies the defaults.
type Options struct {
	// MaxBytes is the maximum raw input size; default DefaultMaxBytes.
	MaxBytes int64
	// MaxItems is the maximum number of components, findings or VEX statements (each counted
	// separately) in the normalized document; default DefaultMaxItems.
	MaxItems int
	// MaxDepth is the maximum JSON nesting depth; default DefaultMaxDepth.
	MaxDepth int
}

func (o Options) withDefaults() Options {
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultMaxBytes
	}
	if o.MaxItems <= 0 {
		o.MaxItems = DefaultMaxItems
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	return o
}

// parserFunc normalizes one format. data has passed checkJSON.
type parserFunc func(data []byte, b *builder) error

var parsers = map[evidence.Format]parserFunc{
	evidence.FormatCycloneDX:   parseCycloneDX,
	evidence.FormatSPDX:        parseSPDX,
	evidence.FormatSARIF:       parseSARIF,
	evidence.FormatGrype:       parseGrype,
	evidence.FormatGovulncheck: parseGovulncheck,
	evidence.FormatOpenVEX:     parseOpenVEX,
}

// Parse reads at most opts.MaxBytes from r and normalizes it as format. An empty format means
// "detect it" (see Detect). The returned Document has deduplicated findings.
func Parse(format evidence.Format, r io.Reader, opts Options) (*evidence.Document, error) {
	if r == nil {
		return nil, fmt.Errorf("normalize: %w: nil reader", ErrInvalid)
	}
	opts = opts.withDefaults()
	data, err := io.ReadAll(io.LimitReader(r, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("normalize: read evidence: %w", err)
	}
	return ParseBytes(format, data, opts)
}

// ParseBytes is Parse for input already in memory (for example after the ingest handler hashed
// and stored the raw document). It enforces the same limits.
func ParseBytes(format evidence.Format, data []byte, opts Options) (*evidence.Document, error) {
	opts = opts.withDefaults()
	if int64(len(data)) > opts.MaxBytes {
		return nil, fmt.Errorf("normalize: %w: more than %d bytes", ErrTooLarge, opts.MaxBytes)
	}
	data = trimBOM(data)
	if format == "" {
		detected, err := Detect(data)
		if err != nil {
			return nil, fmt.Errorf("normalize: %w", err)
		}
		format = detected
	}
	parse, ok := parsers[format]
	if !ok {
		return nil, fmt.Errorf("normalize: %w: %q", ErrUnknownFormat, clip(string(format), 64))
	}
	if err := checkJSON(data, opts.MaxDepth, format == evidence.FormatGovulncheck); err != nil {
		return nil, fmt.Errorf("normalize %s: %w", format, err)
	}
	b := newBuilder(format, len(data), opts)
	if err := parse(data, b); err != nil {
		return nil, fmt.Errorf("normalize %s: %w", format, err)
	}
	b.doc.Findings = Dedupe(b.doc.Findings)
	return b.doc, nil
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// trimBOM drops a leading UTF-8 byte order mark, which some Windows tools emit.
func trimBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, utf8BOM)
}

// invalidf returns an ErrInvalid-wrapping error.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// unsupportedVersion returns an ErrUnsupportedVersion-wrapping error naming the offending value.
func unsupportedVersion(field, value string) error {
	return fmt.Errorf("%w: %s %q", ErrUnsupportedVersion, field, clip(value, 64))
}
