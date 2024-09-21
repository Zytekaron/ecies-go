package main

import (
	"errors"
	"strings"
)

// Flag struct holds information for each valid flag
type Flag struct {
	Name        string
	Shorthand   string
	Description string
	HasValue    bool
}

// FlagSet struct holds all valid flags, parsed results, and remaining args
type FlagSet struct {
	Flags         map[string]Flag
	ParsedArgs    map[string]string
	RemainingArgs []string
}

// NewFlagSet initializes a new FlagSet
func NewFlagSet() *FlagSet {
	return &FlagSet{
		Flags:      make(map[string]Flag),
		ParsedArgs: make(map[string]string),
	}
}

// AddFlag adds a new valid flag to the set
func (fs *FlagSet) AddFlag(name, shorthand, description string, hasValue bool) {
	fs.Flags[name] = Flag{Name: name, Shorthand: shorthand, Description: description, HasValue: hasValue}
	fs.Flags[shorthand] = Flag{Name: name, Shorthand: shorthand, Description: description, HasValue: hasValue}
}

// Parse parses command-line arguments and collects remaining args
func (fs *FlagSet) Parse(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			fs.RemainingArgs = append(fs.RemainingArgs, args[i:]...)
			continue
		}

		if strings.HasPrefix(arg, "--") {
			flagName := arg[2:]
			if flag, ok := fs.Flags[flagName]; ok && flag.HasValue {
				if i+1 < len(args) {
					fs.ParsedArgs[flag.Name] = args[i+1]
					i++
				}
			} else if ok {
				fs.ParsedArgs[flag.Name] = "true"
			} else {
				// Invalid flag, move to remaining args
				fs.RemainingArgs = append(fs.RemainingArgs, arg)
			}
		} else if strings.HasPrefix(arg, "-") {
			shortFlags := arg[1:]
			for j := 0; j < len(shortFlags); j++ {
				flagChar := string(shortFlags[j])
				if flag, ok := fs.Flags[flagChar]; ok {
					if flag.HasValue {
						if j == len(shortFlags)-1 && i+1 < len(args) {
							fs.ParsedArgs[flag.Name] = args[i+1]
							i++
							break
						} else {
							return errors.New("missing arg")
						}
					} else {
						fs.ParsedArgs[flag.Name] = "true"
					}
				} else {
					// Invalid flag, move to remaining args
					fs.RemainingArgs = append(fs.RemainingArgs, arg)
					break
				}
			}
		} else {
			// Non-flag, move to remaining args
			fs.RemainingArgs = append(fs.RemainingArgs, arg)
		}
	}

	return nil
}
