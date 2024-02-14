package utils

import (
	"bufio"
	"fmt"
	"os"
)

func ExtractLinesFromFileOrString(s string) (o []string) {
	var err error
	if o, err = readLines(s); err != nil {
		o = []string{s}
	}
	return o
}

func WriteLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
