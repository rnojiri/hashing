package hashing_test

import (
	"testing"

	"github.com/rnojiri/hashing"
)

// TestSHA256FromByteArray - tests the sha256 implementation
func TestSHA256FromByteArray(t *testing.T) {

	expected := "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
	algorithm := hashing.SHA256

	results, err := hashing.GenerateSHA256FromByteArray([]byte(testString))
	testResults(t, algorithm, expected, results, err)

	results, err = hashing.GenerateFromByteArray(algorithm, []byte(testString))
	testResults(t, algorithm, expected, results, err)
}

// TestSHA1FromByteArray - tests the sha1 implementation
func TestSHA1FromByteArray(t *testing.T) {

	expected := "430ce34d020724ed75a196dfc2ad67c77772d169"
	algorithm := hashing.SHA1

	results, err := hashing.GenerateSHA1FromByteArray([]byte(testString))
	testResults(t, algorithm, expected, results, err)

	results, err = hashing.GenerateFromByteArray(algorithm, []byte(testString))
	testResults(t, algorithm, expected, results, err)
}

// TestCRC32FromByteArray - tests the crc32 implementation
func TestCRC32FromByteArray(t *testing.T) {

	expected := "03b4c26d"
	algorithm := hashing.CRC32

	results, err := hashing.GenerateCRC32FromByteArray([]byte(testString))
	testResults(t, algorithm, expected, results, err)

	results, err = hashing.GenerateFromByteArray(algorithm, []byte(testString))
	testResults(t, algorithm, expected, results, err)
}

// TestMD5FromByteArray - tests the md5 implementation
func TestMD5FromByteArray(t *testing.T) {

	expected := "fc3ff98e8c6a0d3087d515c0473f8677"
	algorithm := hashing.MD5

	results, err := hashing.GenerateMD5FromByteArray([]byte(testString))
	testResults(t, algorithm, expected, results, err)

	results, err = hashing.GenerateFromByteArray(algorithm, []byte(testString))
	testResults(t, algorithm, expected, results, err)
}

// TestShake256FromByteArray - tests the shake 256 implementation
func TestShake256FromByteArray(t *testing.T) {

	size := []int{4, 8, 16, 32}
	expectedHash := []string{
		"1237cfe4",
		"1237cfe493413ac8",
		"1237cfe493413ac80f7b6b41369f7afa",
		"1237cfe493413ac80f7b6b41369f7afa4a3ada93e7edf8de9f93e476796f9aa1",
	}
	algorithm := hashing.SHAKE256

	for i := 0; i < len(size); i++ {

		results, err := hashing.GenerateSHAKE256FromByteArray(size[i], []byte(testString))
		testResults(t, algorithm, expectedHash[i], results, err)

		results, err = hashing.GenerateSHAKEFromByteArray(algorithm, size[i], []byte(testString))
		testResults(t, algorithm, expectedHash[i], results, err)
	}
}

// TestShake128FromByteArray - tests the shake 128 implementation
func TestShake128FromByteArray(t *testing.T) {

	size := []int{4, 8, 16, 32}
	expectedHash := []string{
		"15372b0f",
		"15372b0f35229f5f",
		"15372b0f35229f5fa04f4a262efd609d",
		"15372b0f35229f5fa04f4a262efd609d79f9958d46f9693df968c821f6b2bfda",
	}
	algorithm := hashing.SHAKE128

	for i := 0; i < len(size); i++ {

		results, err := hashing.GenerateSHAKE128FromByteArray(size[i], []byte(testString))
		testResults(t, algorithm, expectedHash[i], results, err)

		results, err = hashing.GenerateSHAKEFromByteArray(algorithm, size[i], []byte(testString))
		testResults(t, algorithm, expectedHash[i], results, err)
	}
}
