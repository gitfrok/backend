package main

// mountChecker makes the FUSE guard directly testable while keeping production probing at the
// process boundary rather than making repository logic know about filesystems.
type mountChecker interface {
	Check(root string) error
}
