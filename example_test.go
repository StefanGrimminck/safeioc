package safeioc_test

import (
	"fmt"

	"github.com/StefanGrimminck/safeioc"
)

func ExampleObfuscate() {
	fmt.Println(safeioc.Obfuscate("https://malicious.example/path"))
	fmt.Println(safeioc.Obfuscate("phish@target.example"))
	fmt.Println(safeioc.Obfuscate("198.51.100.7:4444"))
	// Output:
	// [https]://malicious[.]example/path
	// phish[@]target[.]example
	// 198[.]51[.]100[.]7:4444
}

func ExampleObfuscate_ipv6() {
	fmt.Println(safeioc.Obfuscate("http://[2001:db8::1]:8080"))
	fmt.Println(safeioc.Obfuscate("2001:db8::/32"))
	// Output:
	// [http]://[2001[:]db8[:][:]1]:8080
	// 2001[:]db8[:][:]/32
}

// URLs, email addresses and IP addresses in the path, query or fragment
// are obfuscated too; the rest of the path is kept as it is.
func ExampleObfuscate_nested() {
	fmt.Println(safeioc.Obfuscate("http://example.com/r?url=http://evil.example/a.php&to=abuse@evil.example"))
	// Output: [http]://example[.]com/r?url=[http]://evil[.]example/a.php&to=abuse[@]evil[.]example
}

// Obfuscate can be applied to input that is already (partly) obfuscated.
func ExampleObfuscate_idempotent() {
	fmt.Println(safeioc.Obfuscate("[https]://evil.example"))
	fmt.Println(safeioc.Obfuscate("[https]://evil[.]example"))
	// Output:
	// [https]://evil[.]example
	// [https]://evil[.]example
}

func ExampleDeobfuscate() {
	fmt.Println(safeioc.Deobfuscate("[https]://malicious[.]example/path"))
	// Output: https://malicious.example/path
}

// The legacy "hxxp" and "hxxps" schemes are restored too.
func ExampleDeobfuscate_legacy() {
	fmt.Println(safeioc.Deobfuscate("hxxps://bad[.]example"))
	// Output: https://bad.example
}

func ExampleObfuscateText() {
	report := `The dropper (https://evil.example/stage2.ps1) beacons to 198.51.100.7.
Phishing mail came from billing@target.example, see notes.txt.`
	fmt.Println(safeioc.ObfuscateText(report))
	// Output:
	// The dropper ([https]://evil[.]example/stage2.ps1) beacons to 198[.]51[.]100[.]7.
	// Phishing mail came from billing[@]target[.]example, see notes.txt.
}

// DeobfuscateText restores obfuscated indicators and leaves other bracketed
// text, such as a regular expression, alone.
func ExampleDeobfuscateText() {
	fmt.Println(safeioc.DeobfuscateText("C2 at hxxps://evil[.]example, matched by [a-z]+[.]example"))
	// Output: C2 at https://evil.example, matched by [a-z]+[.]example
}

func ExampleIsObfuscated() {
	for _, s := range []string{"https://evil.example", "[https]://evil[.]example", "[https]://evil.example"} {
		complete := safeioc.Obfuscate(s) == s
		fmt.Printf("%-26s obfuscated=%-5v complete=%v\n", s, safeioc.IsObfuscated(s), complete)
	}
	// Output:
	// https://evil.example       obfuscated=false complete=false
	// [https]://evil[.]example   obfuscated=true  complete=true
	// [https]://evil.example     obfuscated=true  complete=false
}
