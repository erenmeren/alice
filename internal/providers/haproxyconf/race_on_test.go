//go:build race

package haproxyconf

// raceSlowdown scales the time limits of the hostile-size tests: the race detector makes the
// lexer about ten times slower.
const raceSlowdown = 10
