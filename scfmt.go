package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	O1 = 1 << 24
	O2 = 1 << 16
	O3 = 1 << 8
	O4 = 1 << 0
)

func main() {
	escFlag := flag.Bool("e", false, "Builds the payload from an objdump")
	slvFlag := flag.String("s", "", "Converts a string in literal 64b hex values in little endian")
	ipcFlag := flag.String("i", "", "Converts an IP address to an integer")
	flag.Parse()

	log.SetFlags(0)

	if *escFlag {
		extractShellCode()
		os.Exit(0)
	} else if *slvFlag != "" {
		stringLiteralValue(*slvFlag)
	} else if *ipcFlag != "" {
		convIPAddress(*ipcFlag)
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

func convIPAddress(s string) {
	// (first octet * 256³) + (second octet * 256²) + (third octet * 256) + (fourth octet)
	// (first octet * 16777216) + (second octet * 65536) + (third octet * 256) + (fourth octet)

	var octets []int

	for _, o := range strings.Split(s, ".") {
		i, err := strconv.Atoi(o)
		if err != nil {
			log.Fatal(err)
		}

		octets = append(octets, i)
	}

	ipInt := (octets[0] * O1) + (octets[1] * O2) + (octets[2] * O3) + (octets[3] * O4)

	fmt.Printf("IP: %s\n", s)
	fmt.Printf("Int: %d\n", ipInt)
	fmt.Printf("Hex BE: 0x%x\n", ipInt)

	be := strconv.FormatInt(int64(ipInt), 16)
	fmt.Printf("Hex LE: 0x%s%s%s%s\n", be[6:8], be[4:6], be[2:4], be[0:2])

	// var le string
	// for i := len(be) - 1; i > 0; i -= 2 {

	// }
}
