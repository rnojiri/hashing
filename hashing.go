package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"hash/crc32"
	"reflect"

	"golang.org/x/crypto/sha3"
)

/**
* Has hashing functions that produce byte array hashes.
* (no support for blake2b)
* @author rnojiri
**/

// Algorithm - the algorithm constant type
type Algorithm string

const (
	// SHA256 - constant
	SHA256 Algorithm = "sha256"

	// SHA1 - constant
	SHA1 Algorithm = "sha1"

	// MD5 - constant
	MD5 Algorithm = "md5"

	// CRC32 - constant
	CRC32 Algorithm = "crc32"

	// SHAKE128 - constant
	SHAKE128 Algorithm = "shake128"

	// SHAKE256 - constant
	SHAKE256 Algorithm = "shake256"
)

// GenerateByteArray - generates a new byte array based on the given parameters
func GenerateByteArray(parameters ...interface{}) ([]byte, error) {

	if len(parameters) == 0 {
		return nil, nil
	}

	result := []byte{}

	for _, p := range parameters {

		bytes, err := getByteArray(reflect.ValueOf(p))
		if err != nil {
			return nil, err
		}

		result = append(result, bytes...)
	}

	return result, nil
}

// generateHashFromByteArray - the main raw process
func generateHashFromByteArray(h hash.Hash, byteArray []byte) ([]byte, error) {

	_, err := h.Write(byteArray)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// generateShakeHashFromByteArray - the main raw process for shake hash
func generateShakeHashFromByteArray(h sha3.ShakeHash, outputSize int, byteArray []byte) ([]byte, error) {

	_, err := h.Write(byteArray)
	if err != nil {
		return nil, err
	}

	output := make([]byte, outputSize)
	_, err = h.Read(output)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// generateHashUsingInterfaceParams - the main process
func generateHashUsingInterfaceParams(h hash.Hash, parameters ...interface{}) ([]byte, error) {

	byteArray, err := GenerateByteArray(parameters...)
	if err != nil {
		return nil, err
	}

	return generateHashFromByteArray(h, byteArray)
}

// generateShakeHashUsingInterfaceParams - the main process for shake hash
func generateShakeHashUsingInterfaceParams(h sha3.ShakeHash, outputSize int, parameters ...interface{}) ([]byte, error) {

	byteArray, err := GenerateByteArray(parameters...)
	if err != nil {
		return nil, err
	}

	return generateShakeHashFromByteArray(h, outputSize, byteArray)
}

// GenerateSHA256 - generates a sha256 hash based on the specified parameters
func GenerateSHA256(parameters ...interface{}) ([]byte, error) {

	return generateHashUsingInterfaceParams(sha256.New(), parameters...)
}

// GenerateCRC32 - generates a sha256 hash based on the specified parameters
func GenerateCRC32(parameters ...interface{}) ([]byte, error) {

	return generateHashUsingInterfaceParams(crc32.NewIEEE(), parameters...)
}

// GenerateMD5 - generates a md5 hash based on the specified parameters
func GenerateMD5(parameters ...interface{}) ([]byte, error) {

	return generateHashUsingInterfaceParams(md5.New(), parameters...)
}

// GenerateSHA1 - generates a sha1 hash based on the specified parameters
func GenerateSHA1(parameters ...interface{}) ([]byte, error) {

	return generateHashUsingInterfaceParams(sha1.New(), parameters...)
}

// GenerateSHAKE128 - generates a shake128 hash based on the specified parameters
func GenerateSHAKE128(outputSize int, parameters ...interface{}) ([]byte, error) {

	return generateShakeHashUsingInterfaceParams(sha3.NewShake128(), outputSize, parameters...)
}

// GenerateSHAKE256 - generates a shake256 hash based on the specified parameters
func GenerateSHAKE256(outputSize int, parameters ...interface{}) ([]byte, error) {

	return generateShakeHashUsingInterfaceParams(sha3.NewShake256(), outputSize, parameters...)
}

// Generate - generates the hash using the selected algorithm
func Generate(algorithm Algorithm, parameters ...interface{}) ([]byte, error) {

	switch algorithm {
	case SHA256:
		return GenerateSHA256(parameters...)
	case SHA1:
		return GenerateSHA1(parameters...)
	case MD5:
		return GenerateMD5(parameters...)
	case CRC32:
		return GenerateCRC32(parameters...)
	default:
		return nil, fmt.Errorf("no algorithm named %s", algorithm)
	}
}

// GenerateSHAKE - generates the shake hash using the selected algorithm
func GenerateSHAKE(algorithm Algorithm, outputSize int, parameters ...interface{}) ([]byte, error) {

	switch algorithm {
	case SHAKE128:
		return GenerateSHAKE128(outputSize, parameters...)
	case SHAKE256:
		return GenerateSHAKE256(outputSize, parameters...)
	default:
		return nil, fmt.Errorf("no algorithm named %s", algorithm)
	}
}

// Byte array

// GenerateSHA256FromByteArray - generates a sha256 hash based on the specified parameters
func GenerateSHA256FromByteArray(byteArray []byte) ([]byte, error) {

	return generateHashFromByteArray(sha256.New(), byteArray)
}

// GenerateCRC32FromByteArray - generates a sha256 hash based on the specified parameters
func GenerateCRC32FromByteArray(byteArray []byte) ([]byte, error) {

	return generateHashFromByteArray(crc32.NewIEEE(), byteArray)
}

// GenerateMD5FromByteArray - generates a md5 hash based on the specified parameters
func GenerateMD5FromByteArray(byteArray []byte) ([]byte, error) {

	return generateHashFromByteArray(md5.New(), byteArray)
}

// GenerateSHA1FromByteArray - generates a sha1 hash based on the specified parameters
func GenerateSHA1FromByteArray(byteArray []byte) ([]byte, error) {

	return generateHashFromByteArray(sha1.New(), byteArray)
}

// GenerateSHAKE128FromByteArray - generates a shake128 hash based on the specified parameters
func GenerateSHAKE128FromByteArray(outputSize int, byteArray []byte) ([]byte, error) {

	return generateShakeHashFromByteArray(sha3.NewShake128(), outputSize, byteArray)
}

// GenerateSHAKE256FromByteArray - generates a shake256 hash based on the specified parameters
func GenerateSHAKE256FromByteArray(outputSize int, byteArray []byte) ([]byte, error) {

	return generateShakeHashFromByteArray(sha3.NewShake256(), outputSize, byteArray)
}

// GenerateFromByteArray - generates the hash using the selected algorithm
func GenerateFromByteArray(algorithm Algorithm, byteArray []byte) ([]byte, error) {

	switch algorithm {
	case SHA256:
		return GenerateSHA256FromByteArray(byteArray)
	case SHA1:
		return GenerateSHA1FromByteArray(byteArray)
	case MD5:
		return GenerateMD5FromByteArray(byteArray)
	case CRC32:
		return GenerateCRC32FromByteArray(byteArray)
	default:
		return nil, fmt.Errorf("no algorithm named %s", algorithm)
	}
}

// GenerateSHAKEFromByteArray - generates the shake hash using the selected algorithm
func GenerateSHAKEFromByteArray(algorithm Algorithm, outputSize int, byteArray []byte) ([]byte, error) {

	switch algorithm {
	case SHAKE128:
		return GenerateSHAKE128FromByteArray(outputSize, byteArray)
	case SHAKE256:
		return GenerateSHAKE256FromByteArray(outputSize, byteArray)
	default:
		return nil, fmt.Errorf("no algorithm named %s", algorithm)
	}
}
