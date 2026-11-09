package twofactor

import (
	"context"
	"crypto/rand"
	"io"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

// https://github.com/AtomicNibble/twofactor/blob/master/recovery.go | commit: 2b0ae4f

const (
	alphabet           = "ABCDEFGHIJKMNOPQRSTUVWXYZ0123456789"
	recoveryCodeLength = 12
)

var (
	rgx = regexp.MustCompile(`^[0-9A-Z]{6}-[0-9A-Z]{6}$`)
)

// ValidRecoveryCode returns true if the code matches recovery code format
func ValidRecoveryCode(code string) bool {
	return rgx.MatchString(code)
}

// GenerateRecoveryCodes creates 10 recovery codes of the form:
//
// abd34-1b24do (using alphabet, of length recoveryCodeLength).
func GenerateRecoveryCodes() ([]string, error) {
	byt := make([]byte, 10*recoveryCodeLength)
	if _, err := io.ReadFull(rand.Reader, byt); err != nil {
		return nil, err
	}

	codes := make([]string, 10)
	for i := range codes {
		builder := new(strings.Builder)
		for j := 0; j < recoveryCodeLength; j++ {
			if recoveryCodeLength/2 == j {
				builder.WriteByte('-')
			}

			randNumber := byt[i*recoveryCodeLength+j] % byte(len(alphabet))
			builder.WriteByte(alphabet[randNumber])
		}
		codes[i] = builder.String()
	}

	return codes, nil
}

// BCryptRecoveryCodes hashes each recovery code given and return them in a new
// slice.
func BCryptRecoveryCodes(codes []string) ([]string, error) {
	num := len(codes)
	cryptedCodes := make([]string, num)

	g, _ := errgroup.WithContext(context.Background())

	for i, c := range codes {
		i, c := i, c // https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {

			hash, err := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
			if err != nil {
				return err
			}

			cryptedCodes[i] = string(hash)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return cryptedCodes, nil
}

// UseRecoveryCode deletes the code that was used from the string slice and
// returns it, the bool is true if a code was used
func UseRecoveryCode(codes []string, inputCode string) ([]string, bool) {
	input := []byte(inputCode)
	use := -1

	for i, c := range codes {
		err := bcrypt.CompareHashAndPassword([]byte(c), input)
		if err == nil {
			use = i
			break
		}
	}

	if use < 0 {
		return nil, false
	}

	ret := make([]string, len(codes)-1)
	for j := range codes {
		if j == use {
			continue
		}
		set := j
		if j > use {
			set--
		}
		ret[set] = codes[j]
	}

	return ret, true
}

// EncodeRecoveryCodes is an alias for strings.Join(",")
func EncodeRecoveryCodes(codes []string) string { return strings.Join(codes, ",") }

// DecodeRecoveryCodes is an alias for strings.Split(",")
func DecodeRecoveryCodes(codes string) []string { return strings.Split(codes, ",") }
