package saws

/*
#include <pbc/pbc.h>
#include <include/bls.h>
#include <include/port.h>
*/
import "C"
import (
	// "runtime"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"os"

	"github.com/Nik-U/pbc"
)

var pairing = getPairing()

const (
	// PrivateKeySize is the Byte length of a Private Key
	PrivateKeySize = 390
	// PublicKeySize is the Byte length of a Public Key
	PublicKeySize = 393
	// QueryResponseSize is the Byte length of a Query Response
	QueryResponseSize = 259
)

// PublicKey is a structure holding all the necessary elements alpha, g and v=g^x.
type PublicKey struct {
	Alpha pbc.Element
	G     *pbc.Element
	V     pbc.Element
}

func (pubkey PublicKey) String() string {
	return "Alpha: " + pubkey.Alpha.String() +
		"\ng: " + pubkey.G.String() +
		"\nv: " + pubkey.V.String()
}

// PrivateKey is a data structure container for alpha, g and secret x.
type PrivateKey struct {
	Alpha pbc.Element
	G     pbc.Element
	X     pbc.Element
}

func (pkey PrivateKey) String() string {
	return "Alpha: " + pkey.Alpha.String() +
		"\ng: " + pkey.G.String() +
		"\nx: " + pkey.X.String()
}

// QueryResponse is a container for Sigma and Mu
type QueryResponse struct {
	Sigma pbc.Element
	Mu    pbc.Element
}

// Query is a container for the query.
type Query struct {
	I  []uint32
	Nu []pbc.Element
}

func (q Query) String() string {
	retString := fmt.Sprint(q.I) + "\n"
	for i := 0; i < len(q.Nu); i++ {
		retString += q.Nu[i].String() + ", "
	}
	return retString
}
func (q QueryResponse) String() string {
	return "Sigma: " + q.Sigma.String() +
		"\nMu: " + q.Mu.String()
}

// ParsePublicKey parses the data and return the Public Key data structure
func ParsePublicKey(data []byte) (pkey PublicKey, err error) {
	err = nil
	if len(data) != PublicKeySize {
		err = errors.New("Invalid size for Public Key")
		return pkey, err
	}

	alpha := pairing.NewG1().SetCompressedBytes(data[0:C.G1_LEN_COMPRESSED])
	g := pairing.NewG2().SetCompressedBytes(data[C.G1_LEN_COMPRESSED : 2*C.G1_LEN_COMPRESSED])
	v := pairing.NewG1().SetCompressedBytes(data[2*C.G1_LEN_COMPRESSED:])

	if v == nil {
		errors.New("v is Nil")
		return pkey, err
	}
	if g == nil {
		errors.New("g is Nil")
		return pkey, err
	}
	if alpha == nil {
		err = errors.New("alpha is Nil")
		return pkey, err
	}

	pkey.Alpha = *alpha
	pkey.G = g
	pkey.V = *v

	return pkey, err
}

// ParsePrivateKey parses bytes to obtain the Private Key data structure
func ParsePrivateKey(data []byte) (pkey PrivateKey, err error) {
	err = nil
	if len(data) != PrivateKeySize {
		err = errors.New("Invalid size for Private Key")
		return pkey, err
	}

	alpha := pairing.NewG1().SetCompressedBytes(data[0:C.G1_LEN_COMPRESSED])
	g := pairing.NewG2().SetCompressedBytes(data[C.G1_LEN_COMPRESSED : 2*C.G1_LEN_COMPRESSED])
	x := pairing.NewZr().SetBytes(data[2*C.G1_LEN_COMPRESSED:])

	if x == nil {
		errors.New("v is Nil")
		return pkey, err
	}
	if g == nil {
		errors.New("g is Nil")
		return pkey, err
	}
	if alpha == nil {
		err = errors.New("alpha is Nil")
		return pkey, err
	}

	pkey.Alpha = *alpha
	pkey.G = *g
	pkey.X = *x

	return pkey, err
}

// ParseQueryResponse parses bytes to obtain Sigma and Mu and returns a QueryResponse data structure
func ParseQueryResponse(data []byte) (q QueryResponse, err error) {
	err = nil
	if len(data) != QueryResponseSize {
		err = errors.New("Invalid length of query response buffer")
		return q, err
	}

	sigma := pairing.NewG1().SetCompressedBytes(data[:C.G1_LEN_COMPRESSED])
	mu := pairing.NewZr().SetBytes(data[C.G1_LEN_COMPRESSED:])
	q.Sigma = *sigma
	q.Mu = *mu
	return q, nil
}

// ParseQuery parses bytes to return a Query Data Structure
func ParseQuery(data []byte) (q Query, err error) {
	if (len(data)-4)%(132) != 0 {
		return q, errors.New("Invalid query length")
	}

	units := binary.LittleEndian.Uint32(data[:4])
	data = data[4:]
	q.I = make([]uint32, units)
	q.Nu = make([]pbc.Element, units)
	start := 0
	for idx := 0; idx < len(data); idx += 4 + C.ZR_LEN {
		num := binary.LittleEndian.Uint32(data[idx : idx+4])
		q.I[start] = num
		nuTemp := pairing.NewZr().SetBytes(data[idx+4 : idx+4+C.ZR_LEN])

		q.Nu[start] = *nuTemp
		start++
	}
	return q, nil
}

func getPairing() *pbc.Pairing {
	p, _ := pbc.NewPairingFromString(C.a1_param)
	return p
}

func hashInt(i uint32) pbc.Element {
	iStr := fmt.Sprint(i)
	return *pairing.NewG1().SetFromHash([]byte(iStr))
}

// GenerateAudit generates a random byte stream where 4 bytes lie in [1, limit]
func GenerateAudit(seed, limit int64) []byte {
	var ret []byte

	rand.Seed(seed)
	iters := int(rand.Uint64() % 100)

	for i := 0; i < iters; i++ {
		b := make([]byte, 8)
		num := int64(rand.Intn(int(limit)))
		binary.BigEndian.PutUint64(b, uint64(num))
		v := pairing.NewG1().Rand()
		ret = append(ret, b...)
		ret = append(ret, v.Bytes()...)
	}
	return ret
}

/*
 * 	verifyProof verifies the proof submitted to the network
 *	for failure of a audit
 */

// ApplyQuery verifies the query,public key and query response.
func ApplyQuery(q Query, pubkey PublicKey, qr QueryResponse) bool {
	t1 := pairing.NewGT().Pair(&qr.Sigma, pubkey.G)
	temp1 := pairing.NewG1().Set1()

	for i := 0; i < len(q.I); i++ {
		temp2 := hashInt(q.I[i])
		temp2.PowZn(&temp2, &q.Nu[i])
		temp3 := pairing.NewG1().Set(&pubkey.Alpha)
		temp3.PowZn(temp3, &qr.Mu)
		temp1.Mul(temp3, &temp2)
	}
	t2 := pairing.NewGT().Pair(temp1, &pubkey.V)
	return t1.Equals(t2)
}

// FilePiece is a container for data, parity and tags
type FilePiece struct {
	parity   [12]uint8
	data     []byte
	sigmaTag pbc.Element
}

// ReadFile reads a file and returns an arrat of File Pieces.
func ReadFile(filename string) (fpiece []FilePiece) {
	f, _ := os.Open(filename)
	buf := make([]byte, 1024)
	n := 1024
	for n == 1024 {
		n, _ := f.Read(buf)
		var piece FilePiece
		piece.data = buf
		fpiece = append(fpiece, piece)
		if n < 1024 {
			break
		}
	}
	return fpiece
}

// func main() {
// 	hs, _ := hex.DecodeString("0x0020c06105e63fa5224fa8f4f9ac2d3d467c583e42a488222befd57a7cda8d46c28e808e4105f92c4fad33001d00a83d0fc73fd72e0919a43c778f756c9bf0a36c5e93f3a73ea8754c04a4e711daed0b6fb0fec895932a84282af7e6c75d6caf6b4b405538e6ad5ae59b7e2629c9fd6be8418da7b9ff53820768c9c59481d82b2cc201006c2d56563efc3f3272290997f15e911b2d40aac627b04fec171614aa8ec949da49553135892bbea997b01422503b81a6c5dd42dd2fbf47d269bda43c1d5fcbeda37885332121564bca2a8a3a59b13da7b8fcd9e504d772b705a2d0ae0a49cccfb983220cc6974f1cd4599d14e3f3e4cdcf2eb4a150f042659757fe36d5accd04cd0000868cb3a7e7e2203796a93c1fb2cb3ff51df1e7d9956516cc6273bfa996e29c4831e38d5791d67f7d4c06d8ba84af3bcd9b2362b859a603f960d77d0a5662c3adbd201760284f74b85fe1273b41e913c71d5f67060ceef8e854681a91ab09faf18fa71ecd4489efefb1688ff04be97ce850a10186498c622ee45805880e685cbaf401")
// 	data, _ := ioutil.ReadFile("tests/100Mbtemp-query.dat")
// 	query, _ := ParseQuery(data)
// 	data, _ = ioutil.ReadFile("tests/100Mbtemp-enc.key-response.dat")
// 	qr, _ := ParseQueryResponse(data)
// 	data, _ = ioutil.ReadFile("tests/100Mbtemp-pubkey.key")
// 	pubkey, _ := ParsePublicKey(data)
// 	x := applyQuery(query, pubkey, qr)
// 	fmt.Println(x)
// }
