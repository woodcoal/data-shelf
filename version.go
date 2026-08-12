package main

// buildVersion is replaced by the release build with the value from VERSION.
// Keeping a development fallback makes local `go run` and `go test` useful.
var buildVersion = "dev"
