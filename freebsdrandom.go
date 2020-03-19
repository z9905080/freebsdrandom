package freebsdrandom

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"sync/atomic"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

var (
	ErrWrongInputNumber = errors.New("freebsdrandom: input is <= 0")
)

type reader struct {
	entropy      [32]byte // use to math rand
	dataCounter  uint64
	dataCounterSecond uint64
}

var Reader *reader

func init() {
	r := &reader{}
	n, err := rand.Read(r.entropy[:])
	if err != nil || n != len(r.entropy) {
		panic("not enough entropy to fill freebsdrandom reader at startup")
	}
	Reader = r
}

func (r *reader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Use atomic to store CounterData , CounterDataSecond
	counter := atomic.AddUint64(&r.dataCounter, 1)
	counterSecond := atomic.LoadUint64(&r.dataCounterSecond)

	// if counterData size is over need second uint64 data to store
	if counter == 1<<63 || counter == math.MaxUint64 {
		atomic.AddUint64(&r.dataCounterSecond, 1)
	}


	// make seed to produce new data.
	seed := make([]byte, 64)

	// put data uint64 to seed slice with binary.
	binary.LittleEndian.PutUint64(seed[0:8], counter)
	binary.LittleEndian.PutUint64(seed[8:16], counterSecond)

	// use slice copy avoid address copy.
	copy(seed[32:], r.entropy[:])



	// it's innerCounter inside produce.
	n := 0
	innerCounter := uint64(0)
	innerCounterSecond := uint64(0)
	for n < len(b) {

		binary.LittleEndian.PutUint64(seed[16:24], innerCounter)
		binary.LittleEndian.PutUint64(seed[24:32], innerCounterSecond)

		result := blake2b.Sum512(seed)
		n += copy(b[n:], result[:])


		innerCounter++
		if innerCounter == math.MaxUint64 {
			innerCounterSecond++
		}
	}
	return n, nil
}

func Read(b []byte) { Reader.Read(b) }

func Bytes(n int) []byte {
	b := make([]byte, n)
	Read(b)
	return b
}

func Uint64n(n uint64) (uint64,error) {
	if n == 0 {
		return  0,ErrWrongInputNumber
	}
	
	max := math.MaxUint64 - math.MaxUint64%n
	var r uint64
	b := (*[8]byte)(unsafe.Pointer(&r))[:]
	Read(b)
	for r >= max {
		Read(b)
	}
	return r % n,nil
}

// Intn user range in [0,n]
func Intn(n int) (int,error) {
	if n <= 0 {
		return 0, ErrWrongInputNumber

	}
	randomNum,err := Uint64n(uint64(n))
	if err != nil {
		return 0, err
	}
	return int(randomNum),nil
}

func BigIntn(n *big.Int) *big.Int {
	i, _ := rand.Int(Reader, n)
	return i
}

func Perm(n int) []int {
	m := make([]int, n)
	for i := 1; i < n; i++ {
		j,_ := Intn(i + 1)
		m[i] = m[j]
		m[j] = i
	}
	return m
}

func Shuffle(n int, swap func(i, j int)) error {
	if n < 0 {
		return ErrWrongInputNumber
	}

	for i := n - 1; i > 0; i-- {
		j,_ := Intn(i + 1)
		swap(i, j)
	}

	return nil
}
