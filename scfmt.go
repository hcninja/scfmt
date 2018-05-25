package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

func main() {
	escFlag := flag.Bool("e", false, "Builds the payload from an objdump")
	slvFlag := flag.String("s", "", "Converts a string in literal 64b hex values in little endian")
	flag.Parse()

	log.SetFlags(0)

	if *escFlag {
		extractShellCode()
		os.Exit(0)
	} else if *slvFlag != "" {
		stringLiteralValue(*slvFlag)
	} else {
		fmt.Println("Nothing to do…")
		flag.PrintDefaults()
	}
}

// extractShellCode takes the output of an objdump -d command and generates a payload usable by go
func extractShellCode() {
	var payar []string
	scanner := bufio.NewScanner(os.Stdin)
	re := regexp.MustCompile("([0-9a-f]{2}[[:space:]])")
	isStart := false

	for scanner.Scan() {
		s := scanner.Text()
		if !isStart {
			if strings.HasPrefix(s, "start:") {
				isStart = true
			}

			continue
		}

		if strings.HasPrefix(s, "    ") {
			l1 := re.FindAllString(strings.TrimSpace(strings.Split(s, ":")[1]), -1)
			payar = append(payar, l1...)
		}
	}

	var ps string
	fmt.Printf("// payload length: %d (%#x)\n", len(payar), len(payar))
	fmt.Print("var shellcode string = \"")
	for i, c := range payar {
		if i == len(payar) {
			ps += fmt.Sprintf("x%s", strings.TrimSpace(c))
		} else {
			ps += fmt.Sprintf("\\x%s", strings.TrimSpace(c))
		}

	}
	fmt.Printf("%s\"\n", ps)

	if scanner.Err() != nil {
		fmt.Println(scanner.Err())
	}
}

func stringLiteralValue(s string) {
	var revByteSlice []byte

	for i := len(s) - 1; i > 0; i-- {
		revByteSlice = append(revByteSlice, byte(s[i]))
	}

	for i, b := range revByteSlice {
		if i%8 == 0 && i < len(revByteSlice) {
			fmt.Print("0x")
		} else if i%8 == 7 && i < len(revByteSlice) {
			fmt.Printf("%x\n", b)
		} else {
			fmt.Printf("%x", b)
		}
	}

	fmt.Println("")
}
