package version

import (
	"fmt"
	"runtime"
)

var (
	GitTag = "head"
	GitSha = "dev"
)

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
