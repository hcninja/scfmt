package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func main() {
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
