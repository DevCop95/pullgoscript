package elevate

// MarkerArg is appended to the child command line by RelaunchElevated. If the
// relaunched process still comes up without an elevated token — a declined
// prompt, or a policy that strips the Administrators group from the token —
// main sees this marker and reports the failure instead of relaunching again.
// Without it a token that never elevates would loop forever on UAC prompts.
const MarkerArg = "-elevation-attempted"

// StripMarker removes MarkerArg from args and reports whether it was present.
// main calls this before flag.Parse, which would otherwise reject the internal
// marker as an unknown flag. The input slice is never modified.
func StripMarker(args []string) (clean []string, found bool) {
	clean = make([]string, 0, len(args))
	for _, a := range args {
		if a == MarkerArg {
			found = true
			continue
		}
		clean = append(clean, a)
	}
	return clean, found
}
