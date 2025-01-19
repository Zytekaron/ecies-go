package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/zytekaron/squad"
)

var fs = NewFlagSet()

func init() {
	fs.AddFlag("input", "i", "Input file", true)
	fs.AddFlag("output", "o", "Output file", true)
	fs.AddFlag("count", "n", "Number of shares to generate in total", true)
	fs.AddFlag("threshold", "k", "Number of shares required to recover secret", true)

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatalln("error parsing args:", err)
	}
}

func main() {
	if len(fs.RemainingArgs) == 0 {
		log.Fatalln("hungry...want more args")
	}

	command := fs.RemainingArgs[0]
	args := fs.RemainingArgs[1:]

	var err error
	switch command {
	case "help":
		help()
	case "split":
		err = split(args)
	case "combine":
		err = combine(args)
	}
	if err != nil {
		log.Fatalln("error in op "+command+":", err)
	}
}

func help() {
	// todo
}

func split(args []string) error {
	n, err := strconv.Atoi(fs.ParsedArgs["count"])
	if err != nil {
		return fmt.Errorf("error parsing count: %w", err)
	}
	k, err := strconv.Atoi(fs.ParsedArgs["threshold"])
	if err != nil {
		return fmt.Errorf("error parsing threshold: %w", err)
	}

	// read in the secret

	var input io.Reader
	inputFile := fs.ParsedArgs["input"]
	switch inputFile {
	// input flag is empty: use remaining arguments, or stdin if none
	case "":
		if len(args) == 0 {
			input = os.Stdin
		} else {
			joined := strings.Join(args, " ")
			input = strings.NewReader(joined)
		}
	// input flag is -/0/stdio/stdin: use stdin
	case "-", "0", "std", "stdio", "stdin":
		input = os.Stdin
	// input flag is a file name: open the file
	default:
		file, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("error opening input file: %w", err)
		}
		defer file.Close()
		input = file
	}

	secret, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	// split the secret with shamir

	shares, err := squad.Split(secret, byte(n), byte(k))
	if err != nil {
		return fmt.Errorf("error splitting secret: %w", err)
	}

	nameOption := fs.ParsedArgs["output"]
	nameOptionVar := strings.Contains(nameOption, "{i}") || strings.Contains(nameOption, "{o}")

	// open writers for each share
	for i, share := range shares {
		name := nameOption
		if nameOptionVar {
			name = strings.ReplaceAll(name, "{i}", strconv.Itoa(int(i)))
		} else {
			name += strconv.Itoa(int(i))
		}

		outFile, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("error creating output file '%s': %w", name, err)
		}

		_, err = outFile.Write([]byte{i})
		if err != nil {
			return fmt.Errorf("error writing tag to output file '%s': %w", name, err)
		}
		_, err = outFile.Write(share)
		if err != nil {
			return fmt.Errorf("error writing share to output file '%s': %w", name, err)
		}

		outFile.Close()
	}

	return nil
}

func combine(args []string) error {
	var output io.Writer
	outputFile := fs.ParsedArgs["output"]
	switch outputFile {
	// output flag is empty/-/1/stdio/stdout: use stdout
	case "", "-", "1", "std", "stdio", "stdout":
		output = os.Stdout
	// input flag is a file name: open the file
	default:
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("error opening output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	secrets := map[byte][]byte{}
	for _, fileName := range args {
		data, err := os.ReadFile(fileName)
		if err != nil {
			return fmt.Errorf("error opening share file: %w", err)
		}

		x, share := data[0], data[1:]
		secrets[x] = share
	}

	combined := squad.Combine(secrets)

	_, err := output.Write(combined)
	if err != nil {
		return fmt.Errorf("error writing output: %w", err)
	}
	return nil
}
