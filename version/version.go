package version

import (
	"fmt"
	"runtime"
)

// Various variable filled by the make file via LDFLAGS
var (
	GitTag = "head"
	GitSha = "dev"
)

// Shorts return the version as a string.
func Short() string {

	// Short returns the short version string.
	return fmt.Sprintf(
		"%s %s (%s/%s)",
		GitTag,
		GitSha,
		runtime.GOOS,
		runtime.GOARCH,
	)
}
