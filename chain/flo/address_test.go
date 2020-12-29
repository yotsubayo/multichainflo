package flo_test

import (
	"github.com/renproject/multichain/api/address"
	"github.com/renproject/multichain/chain/flo"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DigiByte", func() {
	Context("when decoding an address", func() {
		It("should work without errors", func() {
			_, err := flo.NewAddressDecoder(&flo.MainNetParams).DecodeAddress(address.Address("DBLsEv4FdFPGrMWzcagDQvoKgUL2CikhMf"))
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
