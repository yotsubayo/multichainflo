package flo_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFlo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Flo Suite")
}
