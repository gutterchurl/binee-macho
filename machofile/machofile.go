package machofile

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	//"encoding/binary"
	"fmt"
	//"io"
	//"log"
	"math"
	"os"
	//"strings"
	//"unicode/utf16"
	//"unicode/utf8"
)

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

/*
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
*/

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
	MFile *macho.File
	Path  string
	//Name             string //import name, apiset or on disk
	//RealName         string //on disk short name
	Sha256 string
	//Sections	   *macho.File.Sections
	//Sections       []*Section
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

	// open file as debug/macho File to populate struct
	if mfile, err := macho.Open(path); err == nil {
		machofile.MFile = mfile
		machofile.Size = size
		// need to loop through these maybe?
		//machofile.Segments = mfile.Segment
		fmt.Printf("fh Magic: %#x\n", mfile.FileHeader.Magic)
		seg := mfile.Segment("__DATA")
		if seg != nil {
			fmt.Println(seg.Addr, seg.Addr+seg.Memsz)
			// prints mem addrs of sections, but need names - map?
			fmt.Println(mfile.Sections)
			//fmt.Println(seg)
		}
	}

	if err := analyzeMachOFile(data, machofile); err != nil {
		return nil, err
	}

	//fmt.Sprintf("{ Path: %s }", machofile.Path)
	fmt.Printf("LoadMachOFile:path: %s\n", machofile.Path)
	//fmt.Printf("LoadMachOFile:sha256: %s\n", machofile.Sha256)
	//fmt.Printf("LoadMachOFile:magic: %d\n", machofile.MFile.Magic)

	return machofile, err
}

// LoadMachOBytes will take a Mach-O file in the form of an in memory byte array and parse it
func LoadMachOBytes(data []byte, name string) (*MachOFile, error) {
	machofile := &MachOFile{Path: name}
	machofile.Size = int64(len(data))
	if err := analyzeMachOFile(data, machofile); err != nil {
		return nil, err
	}
	return machofile, nil
}

// Sha256Sum will calcuate the sha256 of the supplied byte slice
func Sha256Sum(b []byte) (hexsum string) {
	sum := sha256.Sum256(b)
	hexsum = fmt.Sprintf("%x", sum)
	return
}

// analyzeMachOFile is the core parser for Mach-O files
func analyzeMachOFile(data []byte, machofile *MachOFile) error {
	//var err error

	machofile.Sha256 = Sha256Sum(data)

	//create reader at offset 0
	r := bytes.NewReader(data)
	fmt.Printf("r len: %d \n", r.Len())

	// read in MachOHeader
	//(machofile.MFile, err) = macho.NewFile(r)

	/*
		if err = binary.Read(r, binary.LittleEndian, pe.DosHeader); err != nil {
			return fmt.Errorf("Error reading dosHeader from file %s: %v", pe.Path, err)
		}
	*/

	/*
		// read CoffHeader into struct
		pe.CoffHeader = &CoffHeader{}
		if err = binary.Read(r, binary.LittleEndian, pe.CoffHeader); err != nil {
			return fmt.Errorf("Error reading coffHeader in file %s: %v", pe.Path, err)
		}

		// advance reader to start of OptionalHeader(32|32+)
		if _, err = r.Seek(int64(pe.DosHeader.AddressExeHeader)+4+int64(binary.Size(CoffHeader{})), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking to optionalHeader in file %s: %v", pe.Path, err)
		}
	*/
	/*
		// check if pe or pe+, read 2 bytes to get Magic then seek backward two bytes
		var _magic uint16
		if err := binary.Read(r, binary.LittleEndian, &_magic); err != nil {
			return fmt.Errorf("Error reading in magic")
		}

		// check magic, must be a PE or PE+
		if _magic == 0x10b {
			pe.PeType = Pe32
		} else if _magic == 0x20b {
			pe.PeType = Pe32p
		} else {
			return fmt.Errorf("invalid magic, must be PE or PE+")
		}

		if _, err = r.Seek(int64(pe.DosHeader.AddressExeHeader)+4+int64(binary.Size(CoffHeader{})), io.SeekStart); err != nil {
			return fmt.Errorf("Error seeking to optionalHeader in file %s: %v", pe.Path, err)
		}

		// copy the optional headers into their respective structs
		if pe.PeType == Pe32 {
			pe.OptionalHeader = &OptionalHeader32{}
			if err = binary.Read(r, binary.LittleEndian, pe.OptionalHeader); err != nil {
				return fmt.Errorf("Error reading optionalHeader32 in file %s: %v", pe.Path, err)
			}
		} else {
			pe.OptionalHeader = &OptionalHeader32P{}
			if err = binary.Read(r, binary.LittleEndian, pe.OptionalHeader); err != nil {
				return fmt.Errorf("Error reading optionalHeader32p in file %s: %v", pe.Path, err)
			}
		}

		//loop through each section and create Section structs
		sectionsStart := int64(0)
		if pe.PeType == Pe32 {
			sectionsStart = int64(pe.DosHeader.AddressExeHeader) + 4 + int64(binary.Size(CoffHeader{})) + int64(binary.Size(OptionalHeader32{}))
		} else {
			sectionsStart = int64(pe.DosHeader.AddressExeHeader) + 4 + int64(binary.Size(CoffHeader{})) + int64(binary.Size(OptionalHeader32P{}))
		}

		// section start will be the end of the data we keep for Raw headers

		// create slice to hold Section pointers
		pe.Sections = make([]*Section, int(pe.CoffHeader.NumberOfSections))
		pe.sectionHeaders = make([]*SectionHeader, int(pe.CoffHeader.NumberOfSections))

		// loop over each section and populate struct
		for i := 0; i < int(pe.CoffHeader.NumberOfSections); i++ {
			if _, err = r.Seek(sectionsStart+int64(binary.Size(SectionHeader{})*i), io.SeekStart); err != nil {
				return fmt.Errorf("Error seeking over sections in file %s: %v", pe.Path, err)
			}

			temp := SectionHeader{}
			if err = binary.Read(r, binary.LittleEndian, &temp); err != nil {
				return fmt.Errorf("Error reading section[%d] in file %s: %v", i, pe.Path, err)
			}
			pe.sectionHeaders[i] = &temp

			pe.Sections[i] = &Section{}
			pe.Sections[i].Name = string(temp.Name[:8])
			pe.Sections[i].VirtualSize = temp.VirtualSize
			pe.Sections[i].VirtualAddress = temp.VirtualAddress
			pe.Sections[i].Size = temp.Size
			pe.Sections[i].Offset = temp.Offset
			pe.Sections[i].PointerToRelocations = temp.PointerToRelocations
			pe.Sections[i].PointerToLineNumbers = temp.PointerToLineNumbers
			pe.Sections[i].NumberOfRelocations = temp.NumberOfRelocations
			pe.Sections[i].NumberOfLineNumbers = temp.NumberOfLineNumbers
			pe.Sections[i].Characteristics = temp.Characteristics

			if _, err = r.Seek(int64(temp.Offset), io.SeekStart); err != nil {
				return fmt.Errorf("Error seeking offset in section[%s] of file %s: %v", pe.Sections[i].Name, pe.Path, err)
			}
			raw := make([]byte, temp.Size)
			if _, err = r.Read(raw); err != nil {
				if err == io.EOF {
					pe.Sections[i].Raw = nil
					continue
				}
				return fmt.Errorf("Error reading bytes at offset[0x%x] in section[%s] of file %s: %v", pe.Sections[i].Offset, pe.Sections[i].Name, pe.Path, err)
			}
			pe.Sections[i].Raw = raw
			pe.Sections[i].Entropy = entropy(raw)
		}

		pe.RawHeaders = data[0:pe.Sections[0].Offset]
		pe.readImports()
		if err = pe.readExports(); err != nil {
			return err
		}
		pe.readApiset()
	*/

	return nil
}

func readString(b []byte) string {
	for i := 0; ; i++ {
		if b[i] == 0x0 {
			return string(b[0:i])
		}
	}
}
