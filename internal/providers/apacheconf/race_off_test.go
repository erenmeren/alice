//go:build !race

package apacheconf

// raceSlowdown scales the time limits of the hostile-size tests (1 without the race detector).
const raceSlowdown = 1
