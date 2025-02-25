module main

go 1.22.4

require (
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.16
	github.com/salrashid123/go-pqc-wrapping v0.0.0
	google.golang.org/protobuf v1.36.5
)

require (
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	golang.org/x/net v0.24.0 // indirect
)

replace github.com/salrashid123/go-pqc-wrapping => ../
