// Go module versions as the go command reads them: for each input line, module.CanonicalVersion
// (semver.Canonical, keeping +incompatible), or INVALID when semver.IsValid is false.
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func main() {
	f, _ := os.Open(os.Args[1])
	s := bufio.NewScanner(f)
	fmt.Println("# golang.org/x/mod")
	for s.Scan() {
		v := s.Text()
		if !semver.IsValid(v) {
			fmt.Printf("%s\tINVALID\n", v)
			continue
		}
		fmt.Printf("%s\t%s\n", v, module.CanonicalVersion(v))
	}
}
