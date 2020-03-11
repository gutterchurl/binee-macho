package machofile

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// Actually Section64 but leaving it this way for now
type Section struct {
	Name     [16]byte
	Seg      [16]byte
	Addr     uint64
	Size     uint64
	Offset   uint32
	Align    uint32
	Reloff   uint32
	Nreloc   uint32
	Flags    uint32
	Reserve1 uint32
	Reserve2 uint32
	Reserve3 uint32
	//VirtualSize          uint32
	//VirtualAddress       uint32
	PointerToRelocations []*macho.Reloc
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Raw                  []byte
	Entropy              float64
}

type Segment struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Raw                  []byte
	Entropy              float64
}

type MachOFileHeader struct {
	Magic  uint32
	Cpu    macho.Cpu
	SubCpu uint32
	Type   macho.Type
	Ncmd   uint32
	Cmdsz  uint32
	Flags  uint32
}

type MachOFile struct {
	MFile []*macho.File
	Path  string
	//Name             string //import name, apiset or on disk
	//RealName         string //on disk short name
	Sha256         string
	Sections       []*Section
	sectionHeaders []*macho.SectionHeader
	Segments       []*Segment
	segmentHeaders []*macho.SegmentHeader
	Size           int64
	RawHeaders     []byte
	oldImageBase   uint64
	ImageSize      int64
}

func entropy(bs []byte) float64 {
	histo := make([]int, 256)
	for _, b := range bs {
		histo[int(b)]++
	}

	size := len(bs)
	var ret float64 = 0.0

	for _, count := range histo {
		if count == 0 {
			continue
		}

		p := float64(count) / float64(size)
		ret += p * math.Log2(p)
	}

	return -ret
}

func (mo *MachOFile) String() string {
	return fmt.Sprintf("{ Path: %s }", mo.Path)
}

// LoadMachOFile will parse a file from disk, given a path. The output will be a
// MachOFile object or an error
func LoadMachOFile(path string) (*MachOFile, error) {

	// create MachoFile struct
	machofile := &MachOFile{Path: path}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening %s file: %v", path, err)
	}

	// get size of file, then seek back to start to reset the cursor
	size, err := file.Seek(0, 2)
	if err != nil {
		return nil, fmt.Errorf("Error getting size of file %s: %v", path, err)
	}
	file.Seek(0, 0)

	// read the file into data buffer
	data := make([]byte, size)
	if _, err = file.Read(data); err != nil {
		return nil, fmt.Errorf("Error copying file %s into buffer: %v", path, err)
	}
	machofile.Size = size

	/*
		if err := analyzePeFile(data, machofile); err != nil {
			return nil, err
		}
	*/
	return machofile, nil
}
