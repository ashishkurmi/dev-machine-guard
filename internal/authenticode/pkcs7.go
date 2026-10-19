package authenticode

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

const (
	maxSigBlob             = 1 << 20
	winCertTypePKCSSigned  = 0x0002
	imageDirectoryEntrySec = 4
)

var (
	oidSignedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCounterSignature    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidRFC3161CounterSign  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	errMalformedSignedData = errors.New("authenticode: malformed PKCS#7 signature")
)

// Inspect reads the primary signature of a PE file without checking trust:
// the leaf signer subject and whether it carries a timestamp.
func Inspect(path string) (*Signature, error) {
	blob, err := peSignature(path)
	if err != nil {
		return nil, err
	}
	return parseSignedData(blob)
}

// peSignature returns the PKCS#7 SignedData of the first WIN_CERTIFICATE in
// the PE security directory.
func peSignature(path string) ([]byte, error) {
	// #nosec G304 -- the updater's own staged or running executable.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pf, err := pe.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("authenticode: %s is not a PE file: %w", path, err)
	}
	var dir pe.DataDirectory
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > imageDirectoryEntrySec {
			dir = oh.DataDirectory[imageDirectoryEntrySec]
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > imageDirectoryEntrySec {
			dir = oh.DataDirectory[imageDirectoryEntrySec]
		}
	}
	if dir.VirtualAddress == 0 || dir.Size < 8 {
		return nil, ErrUnsigned
	}
	if dir.Size > maxSigBlob {
		return nil, errMalformedSignedData
	}
	buf := make([]byte, dir.Size)
	// The security directory's "VirtualAddress" is a file offset.
	if _, err := f.ReadAt(buf, int64(dir.VirtualAddress)); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(buf[0:4])
	certType := binary.LittleEndian.Uint16(buf[6:8])
	if certType != winCertTypePKCSSigned || length < 8 || length > dir.Size {
		return nil, errMalformedSignedData
	}
	return buf[8:length], nil
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    asn1.RawValue
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm asn1.RawValue
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// parseSignedData extracts the first signer's certificate subject and the
// presence of a (legacy or RFC 3161) countersignature timestamp.
func parseSignedData(der []byte) (*Signature, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(bytes.TrimRight(rest, "\x00")) != 0 {
		return nil, errMalformedSignedData
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errMalformedSignedData
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, errMalformedSignedData
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) == 0 {
		return nil, errMalformedSignedData
	}
	var si signerInfo
	if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err != nil {
		return nil, errMalformedSignedData
	}
	leaf := findSigner(certs, si.SID)
	if leaf == nil {
		return nil, fmt.Errorf("%w: signer certificate not embedded", errMalformedSignedData)
	}
	sig := &Signature{Subject: leaf.Subject.String()}
	rest := si.UnsignedAttrs.Bytes
	for len(rest) > 0 {
		var a attribute
		var err error
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return nil, errMalformedSignedData
		}
		if a.Type.Equal(oidCounterSignature) || a.Type.Equal(oidRFC3161CounterSign) {
			sig.Timestamped = true
		}
	}
	return sig, nil
}

func findSigner(certs []*x509.Certificate, sid asn1.RawValue) *x509.Certificate {
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c
			}
		}
		return nil
	}
	var ias issuerAndSerial
	if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil || ias.Serial == nil {
		return nil
	}
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
			return c
		}
	}
	return nil
}
