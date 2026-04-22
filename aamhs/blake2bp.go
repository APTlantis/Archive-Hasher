package aamhs

import (
	"hash"

	dchestblake2b "github.com/dchest/blake2b"
)

const (
	blake2bpFanout       = 4
	blake2bpDepth        = 2
	blake2bpBlockSize    = 128
	blake2bpDigestSize   = 64
	blake2bpInnerHashLen = 64
)

type blake2bpHasher struct {
	leaves      [blake2bpFanout]hash.Hash
	lane        int
	pending     [blake2bpBlockSize]byte
	pendingSize int
}

func newBLAKE2bpHasher() (*blake2bpHasher, error) {
	h := &blake2bpHasher{}
	for i := range h.leaves {
		leaf, err := dchestblake2b.New(&dchestblake2b.Config{
			Size: blake2bpDigestSize,
			Tree: &dchestblake2b.Tree{
				Fanout:        blake2bpFanout,
				MaxDepth:      blake2bpDepth,
				LeafSize:      0,
				NodeOffset:    uint64(i),
				NodeDepth:     0,
				InnerHashSize: blake2bpInnerHashLen,
				IsLastNode:    i == blake2bpFanout-1,
			},
		})
		if err != nil {
			return nil, err
		}
		h.leaves[i] = leaf
	}
	return h, nil
}

func (h *blake2bpHasher) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		if h.pendingSize == 0 && len(p) >= blake2bpBlockSize {
			_, _ = h.leaves[h.lane].Write(p[:blake2bpBlockSize])
			h.advanceLane()
			p = p[blake2bpBlockSize:]
			continue
		}

		n := copy(h.pending[h.pendingSize:], p)
		h.pendingSize += n
		p = p[n:]
		if h.pendingSize == blake2bpBlockSize {
			_, _ = h.leaves[h.lane].Write(h.pending[:])
			h.pendingSize = 0
			h.advanceLane()
		}
	}
	return written, nil
}

func (h *blake2bpHasher) Sum(b []byte) []byte {
	leaves := h.leaves
	if h.pendingSize > 0 {
		_, _ = leaves[h.lane].Write(h.pending[:h.pendingSize])
	}

	root, err := dchestblake2b.New(&dchestblake2b.Config{
		Size: blake2bpDigestSize,
		Tree: &dchestblake2b.Tree{
			Fanout:        blake2bpFanout,
			MaxDepth:      blake2bpDepth,
			LeafSize:      0,
			NodeOffset:    0,
			NodeDepth:     1,
			InnerHashSize: blake2bpInnerHashLen,
			IsLastNode:    true,
		},
	})
	if err != nil {
		panic(err)
	}

	for i := range leaves {
		_, _ = root.Write(leaves[i].Sum(nil))
	}
	return root.Sum(b)
}

func (h *blake2bpHasher) advanceLane() {
	h.lane = (h.lane + 1) % blake2bpFanout
}
