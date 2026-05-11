module github.com/alatticeio/lattice-shim

go 1.25.8

require gvisor.dev/gvisor v0.0.0-20260509025911-8c9871efe45a

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/time v0.12.0 // indirect
)

replace gvisor.dev/gvisor => github.com/google/gvisor v0.0.0-20260508212337-96dad6a2da94
