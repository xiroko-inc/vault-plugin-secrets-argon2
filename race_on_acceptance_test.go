//go:build acceptance && race

// raceEnabled is true when the test binary itself was compiled with
// -race. Used by cachedPluginBinary to conditionally pass -race
// when building the plugin subprocess, so the plugin's internal
// races are also instrumented.

package argon2id_test

const raceEnabled = true
