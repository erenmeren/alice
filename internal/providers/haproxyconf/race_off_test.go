//go:build !race

package haproxyconf

// raceSlowdown scales the time limits of the hostile-size tests (1 without the race detector).
const raceSlowdown = 1
