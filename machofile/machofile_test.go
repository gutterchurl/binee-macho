package machofile

import "testing"

func TestLoadMachO(t *testing.T) {
	mfile, err := LoadMachOFile("../tests/MachOConsoleApp_x64")
	if err != nil {
		t.Errorf("Error loading %s\n", mfile.Path)
	}

	/*
		if len(pe.ImportedDlls()) != 7 {
			t.Errorf("Wrong number of imported dlls for %s, 7 == %d\n", pe.Path, len(pe.Imports))
		}

		var count int = len(pe.Imports)

		if count != 43 {
			t.Errorf("%s total number of imported functions should be 43 == %d\n", pe.Path, count)
		}
	*/
}

/*
func TestLoadExe2(t *testing.T) {
	pe, err := LoadPeFile("../tests/ConsoleApplication1_x86.exe")
	if err != nil {
		t.Errorf("Error loading %s\n", pe.Path)
	}

	for _, s := range pe.Sections {
		if s.Name == ".text\x00\x00\x00" {
			if s.Entropy != 6.20128067741889 {
				t.Errorf("invalid entropy, got %v", s.Entropy)
			}
		}
	}

}

func TestParsePEplusImports(t *testing.T) {
	pe, err := LoadPeFile("../tests/ConsoleApplication1_x64.exe")
	if err != nil {
		t.Errorf("Error loading %s\n", pe.Path)
	}

	if len(pe.ImportedDlls()) != 8 {
		t.Errorf("invalid number of dlls imported, got %v", len(pe.ImportedDlls()))
	}

	if len(pe.Imports) != 48 {
		t.Errorf("invalid number of imports parsed, got %v", len(pe.Imports))
	}
}
*/
