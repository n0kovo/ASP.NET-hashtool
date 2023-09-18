package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/spf13/pflag"
	"go.uber.org/ratelimit"
	"golang.org/x/crypto/pbkdf2"
)

// Generate a hash and salt from plaintext
func generateHash(plain string, hashMode string, PBKDF2IterCount int, PBKDF2SubkeyLength int, SaltSize int) (string, error) {
	if hashMode == "mvc4" {
		SaltSize = 16
	}
	var encoded string
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	encoded_salt := base64.StdEncoding.EncodeToString(salt)

	if hashMode == "mvc4" {
		// MVC4 Logic
		subkey := pbkdf2.Key([]byte(plain), salt, PBKDF2IterCount, PBKDF2SubkeyLength, sha1.New)
		outputBytes := append([]byte{0}, salt...)
		outputBytes = append(outputBytes, subkey...)
		encoded = base64.StdEncoding.EncodeToString(outputBytes)
	} else if hashMode == "webforms" {
		// WebForms Logic
		hash := sha256.Sum256([]byte(plain))
		combined := append(salt, hash[:]...)
		encoded = base64.StdEncoding.EncodeToString(combined)
		encoded = fmt.Sprintf("%s,%s", encoded, encoded_salt)
	}

	return encoded, nil
}

func convertHash(line string, usernamePresent bool, delimiter string, PBKDF2IterCount int) (string, error) {
	var username, encoded string

	if usernamePresent {
		parts := strings.SplitN(line, delimiter, 2)
		if len(parts) < 2 {
			return "", fmt.Errorf("invalid line format: missing delimiter")
		}
		username = parts[0]
		encoded = strings.TrimSpace(parts[1])
	} else {
		username = ""
		encoded = strings.TrimSpace(line)
	}

	// Decode from Base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("error decoding Base64: %w", err)
	}

	// Drop first byte
	if len(decoded) < 17 {
		return "", fmt.Errorf("decoded bytes too short")
	}
	droppedBytes := decoded[1:]

	// Split the byte slice
	salt, hashDigest := droppedBytes[:16], droppedBytes[16:]

	// Convert each part from bytes to Base64
	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	hashBase64 := base64.StdEncoding.EncodeToString(hashDigest)

	// Merge and add prefix
	var processedLine string
	if usernamePresent {
		processedLine = fmt.Sprintf("%s:sha1:%s:%s:%s", username, PBKDF2IterCount, saltBase64, hashBase64)
	} else {
		processedLine = fmt.Sprintf("sha1:%s:%s:%s", fmt.Sprint(PBKDF2IterCount), saltBase64, hashBase64)
	}

	return processedLine, nil
}

func main() {
	var generateMode bool
	var hashMode string
	var work_type string
	var usernamePresent bool
	var delimiter string
	var wg sync.WaitGroup
	var processedLines int64
	var erroredLines int64
	var rateLimit int
	var maxWorkers int
	var quiet bool

	var PBKDF2IterCount int
	var PBKDF2SubkeyLength int
	var SaltSize int
	var advancedHelp bool

	var help bool
	var sem chan struct{}

	startTime := time.Now()

	pflag.BoolVarP(&generateMode, "generate", "g", false, "generate hashes from plaintext input instead of converting")
	pflag.StringVarP(&hashMode, "mode", "M", "default", "Choose between MVC4 (SimpleMembershipProvider) and WebForms (DefaultMembershipProvider) when generating hashes. Defaults to MVC4")
	pflag.BoolVarP(&usernamePresent, "username", "u", false, "indicates if the input is prefixed with a username")
	pflag.StringVarP(&delimiter, "delimiter", "d", ",", "delimiter to split username and salt+hash if --username is used (default: \",\")")
	pflag.IntVarP(&rateLimit, "rate-limit", "r", 0, "number of lines per second to process. 0 = no limit")
	pflag.IntVarP(&maxWorkers, "max-workers", "m", 0, "maximum number of workers (goroutines) to use. 0 = no limit (default))")

	pflag.IntVarP(&PBKDF2IterCount, "iter", "i", 1000, "[ADVANCED] number of PBKDF2 iterations (default: 1000)")
	pflag.IntVarP(&PBKDF2SubkeyLength, "subkey-length", "l", 32, "[ADVANCED] PBKDF2 subkey length in bytes (default: 32 = 256 bits)")
	pflag.IntVarP(&SaltSize, "salt-size", "s", 16, "[ADVANCED] salt size in bytes (default: 16 = 128 bits)")

	pflag.BoolVarP(&help, "help", "h", false, "print this help message")
	pflag.BoolVarP(&advancedHelp, "advanced-help", "a", false, "print help message for advanced hashing options")
	pflag.BoolVarP(&quiet, "quiet", "q", false, "suppress output")

	pflag.Usage = func() {
		if !advancedHelp {
			fmt.Printf("Usage of %s:\n", os.Args[0])
			fmt.Println("This application either generates or converts ASP.NET MVC4/Web Forms password hashes.")
			fmt.Println("Convert mode (default) reads hashes from stdin and writes hashcat mode 12000 compatible hashes to stdout.")
			fmt.Println("Generate mode (-g) reads plaintext from stdin and writes hashes to stdout.")
			fmt.Println("Flags:")
		} else {
			fmt.Printf("Advanced options:\n")
		}

		pflag.VisitAll(func(flag *pflag.Flag) {
			if advancedHelp {
				if strings.HasPrefix(flag.Usage, "[ADVANCED]") {
					fmt.Printf(" -%s, --%-20s %s\n", flag.Shorthand, flag.Name, strings.TrimPrefix(flag.Usage, "[ADVANCED] "))
				}
			} else if !strings.HasPrefix(flag.Usage, "[ADVANCED]") {
				fmt.Printf(" -%s, --%-20s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			}
		})
		if advancedHelp {
			fmt.Println("\nWARNING: Changing these parameters will result in hashes that are incompatible with ASP.NET.")
		}
	}

	pflag.Parse()

	if advancedHelp {
		pflag.Usage()
		os.Exit(0)
	}

	if help {
		pflag.Usage()
		os.Exit(0)
	}

	// Validate the mode flag
	hashMode = strings.ToLower(hashMode)
	if hashMode != "mvc4" && hashMode != "webforms" && hashMode != "default" {
		log.Fatalf("Invalid mode. Choose between MVC4 and WebForms.")
	}

	// Create max worker semaphore if maxWorkers is set
	if maxWorkers > 0 {
		sem = make(chan struct{}, maxWorkers)
	}

	if generateMode {
		work_type = "lines"
		if hashMode == "default" {
			hashMode = "mvc4"
		}
		if usernamePresent {
			log.Fatalf("Error: --generate and --username flags are mutually exclusive.")
		}
	} else {
		work_type = "hashes"
		if hashMode != "default" {
			log.Fatalf("Error: hash type selection is not supported in convert mode.")
		}
	}

	if delimiter != "," && !usernamePresent {
		log.Fatalf("Error: --delimiter can only be used when --username is also used.")
	}

	// Disable logging if quiet
	if quiet {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(os.Stderr)
	}

	// Rate limiting
	var limiter ratelimit.Limiter
	if rateLimit > 0 {
		limiter = ratelimit.New(rateLimit)
	} else {
		limiter = ratelimit.NewUnlimited()
	}

	log.Printf("Processing %s from stdin...\n\n", work_type)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if maxWorkers > 0 {
			sem <- struct{}{} // Acquire a token if maxWorkers is set
		}

		wg.Add(1)
		if rateLimit > 0 {
			limiter.Take()
		}

		go func(line string) {
			defer wg.Done()
			var result string
			var err error

			if generateMode {
				// Generate hash
				result, err = generateHash(line, hashMode, int(PBKDF2IterCount), int(PBKDF2SubkeyLength), int(SaltSize))
			} else {
				// Convert hash
				result, err = convertHash(line, usernamePresent, delimiter, PBKDF2IterCount)
			}

			if err != nil {
				atomic.AddInt64(&erroredLines, 1)
			} else {
				fmt.Println(result)
				atomic.AddInt64(&processedLines, 1)
			}
			if maxWorkers > 0 {
				<-sem // Release the token if maxWorkers is set
			}
		}(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Stdin scanner encountered an error: %v", err)
	}

	wg.Wait()

	endTime := time.Now()
	totalTime := endTime.Sub(startTime).Seconds()

	// Stats
	if !quiet {
		fmt.Fprintln(os.Stderr)
	}
	log.Printf("Done! Total Run Time: %f seconds", totalTime)
	log.Printf("Processed %d %s", processedLines, work_type)
	log.Printf("Errored %s: %d", work_type, erroredLines)
	if totalTime > 0 {
		r := []rune(work_type)
		r[0] = unicode.ToUpper(r[0])
		work_type = string(r)
		log.Printf("%s per second: %f", work_type, float64(processedLines)/totalTime)
	}
}
