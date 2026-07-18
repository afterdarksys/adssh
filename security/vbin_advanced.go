package security

func init() {
	Register(pickBinary{})
	Register(navBinary{})
	for _, name := range []string{"from", "where", "select", "to"} {
		Register(structuredBinary{name: name})
	}
	Register(whyBinary{})
	Register(runbookBinary{})
	Register(parBinary{})
	Register(evidenceBinary{})
	Register(leaseBinary{})
}
