//go:build race

package apacheconf

// raceSlowdown scales the time limits of the hostile-size tests: the race detector makes the
// lexer about ten times slower.
const raceSlowdown = 10
