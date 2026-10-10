//go:build !linux

package agent

import "frostbite/internal/link"

// sampler has nothing to read on this platform.
type sampler struct{}

func newSampler() *sampler { return &sampler{} }

func (s *sampler) sample() link.Metrics { return link.Metrics{} }

func readMemTotal() uint64 { return 0 }

func readKernel() string { return "" }
