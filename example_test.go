package safeioc_test

import (
	"fmt"

	"github.com/StefanGrimminck/safeioc"
)

func ExampleObfuscate() {
	fmt.Println(safeioc.Obfuscate("https://malicious.example/path"))
	// Output: [https]://malicious[.]example/path
}

func ExampleObfuscate_ipv6() {
	fmt.Println(safeioc.Obfuscate("http://[2001:db8::1]:8080"))
	// Output: [http]://[2001[:]db8[:][:]1]:8080
}

func ExampleObfuscate_email() {
	fmt.Println(safeioc.Obfuscate("phish@target.example"))
	// Output: phish[@]target[.]example
}

func ExampleObfuscate_nestedRedirect() {
	fmt.Println(safeioc.Obfuscate("http://example.com/r?url=http://evil.example"))
	// Output: [http]://example[.]com/r?url=[http]://evil[.]example
}

func ExampleDeobfuscate() {
	fmt.Println(safeioc.Deobfuscate("[https]://malicious[.]example/path"))
	// Output: https://malicious.example/path
}

func ExampleDeobfuscate_legacy() {
	fmt.Println(safeioc.Deobfuscate("hxxps://bad[.]example"))
	// Output: https://bad.example
}
