// Package main is the main entry point into using Binee. Provides all
// parameterized options passed in via command line
package main

import (
	//"debug/macho"
	"flag"
	"fmt"
	"log"

	"github.com/carbonblack/binee/machofile"
	"github.com/carbonblack/binee/macos"
	"github.com/carbonblack/binee/pefile"
	"github.com/carbonblack/binee/util"
	"github.com/carbonblack/binee/windows"
)

func main() {

	isAPISetLookup := flag.String("a", "", "get the real dll name from an apiset name")
	listAllAPISets := flag.Bool("A", false, "list all apisets and their mappings")
	showDLL := flag.Bool("d", false, "show the dll prfix on all function calls")
	configFilePath := flag.String("c", "", "path to configuration file")
	listExports := flag.Bool("e", false, "dump pe file's exports table")
	listImports := flag.Bool("i", false, "dump a pe file's imports table")
	outputJSON := flag.Bool("j", false, "output data as json")
	instructionLog := flag.Bool("l", false, "log instructions to a []*Instruction slice, typically this is for programmatic emulation")
	verbose2 := flag.Bool("vv", false, "verbose level 2")
	verbose1 := flag.Bool("v", false, "verbose level 1")
	runDLLMain := flag.Bool("m", false, "call DLLMain while loading DLLs")
	//machox64 := flag.String("M", "", "specify path to 64-bit mach-o file")
	rootFolder := flag.String("r", "os/win10_32/", "root path of mock file system, defaults to ./os/win10_32")
	maxTicks := flag.Int64("t", 0, "maximum number of instructions to emulate before stopping emulation, default is 0 and will run forever or until other stopping event")

	flag.Parse()

	verboseLevel := 0
	if *verbose1 {
		verboseLevel = 1
	}
	if *verbose2 {
		verboseLevel = 2
	}

	// if apiset dump option, load apisetschema.dll and dump all apisets
	if *listAllAPISets {
		if *configFilePath != "" {
			conf, err := util.ReadGenericConfig(*configFilePath)
			if err != nil {
				log.Fatal(err)
			}
			rootFolder = &conf.Root
		}
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", *rootFolder + "windows/system32"}, "apisetschema.dll")
		if err != nil {
			log.Fatal(err)
		}

		apiset, _ := pefile.LoadPeFile(path)

		for k, v := range apiset.Apisets {
			fmt.Println(k, v)
		}

		return
	}

	// if apiset lookup, load apisetschema.dll and look up the apiset name
	if *isAPISetLookup != "" {
		if *configFilePath != "" {
			conf, err := util.ReadGenericConfig(*configFilePath)
			if err != nil {
				log.Fatal(err)
			}
			rootFolder = &conf.Root
		}
		path, err := util.SearchFile([]string{"C:\\Windows\\System32", *rootFolder + "windows/system32"}, "apisetschema.dll")
		if err != nil {
			log.Fatal(err)
		}

		apiset, _ := pefile.LoadPeFile(path)
		lookup := (*isAPISetLookup)[0 : len(*isAPISetLookup)-6]
		if apiset.Apisets[lookup] != nil {
			for i := 0; i < len(apiset.Apisets[lookup]); i++ {
				fmt.Println("  ", apiset.Apisets[lookup][i])
			}
		} else {
			fmt.Println("apiset not found.")
		}

		return
	}

	// quit if no binary is passed in
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		return
	}

	// print the binaries import table
	if *listImports {
		if pe, err := pefile.LoadPeFile(flag.Arg(0)); err == nil {
			for _, importInfo := range pe.Imports {
				fmt.Printf("%s.%s => 0x%x\n", importInfo.DllName, importInfo.FuncName, importInfo.Offset)
			}
		}
		return
	}

	// print the binaries export table
	if *listExports {
		if pe, err := pefile.LoadPeFile(flag.Arg(0)); err == nil {
			for _, export := range pe.Exports {
				fmt.Println(export.Name)
			}
		}
		return
	}

	if machofile.IsMachO(flag.Arg(0)) {

		options := macos.InitMacEmulatorOptions()
		options.VerboseLevel = verboseLevel
		options.ConfigPath = *configFilePath
		options.RootFolder = *rootFolder
		options.MaxTicks = *maxTicks
		// probably need to change these log functions and put them in util
		// or something
		if *outputJSON {
			options.LogType = windows.LogTypeJSON
		} else if *instructionLog {
			options.LogType = windows.LogTypeSlice
		} else {
			options.LogType = windows.LogTypeStdout
		}

		// test code:

		fmt.Printf("hello mach-o! %s\n", flag.Arg(0))
		m, err := machofile.LoadMachOFile(flag.Arg(0))
		//var cmd macho.LoadCmd
		//fmt.Println(cmd)

		if err != nil {
			log.Fatal(err)
		}

		/*
			if mfile, err := macho.Open(flag.Arg(0)); err == nil {
				seg := mfile.Segment("__DATA")
				if seg != nil {
					fmt.Println(seg.Addr, seg.Addr+seg.Memsz)
					fmt.Println(mfile.Sections)
					//fmt.Println(seg)
				}
			}
		*/
		fmt.Println(m.MFile.Magic)
		fmt.Println(m.MFile.FileHeader.Type)

		// now start the emulator with the various options
		emu, err := macos.Load(flag.Arg(0), flag.Args()[1:], options)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(emu.Binary)
		//emu.Start()

		return
	}

	options := windows.InitWinEmulatorOptions()
	options.VerboseLevel = verboseLevel
	options.ConfigPath = *configFilePath
	options.RootFolder = *rootFolder
	options.ShowDLL = *showDLL
	options.RunDLLMain = *runDLLMain
	if *outputJSON {
		options.LogType = windows.LogTypeJSON
	} else if *instructionLog {
		options.LogType = windows.LogTypeSlice
	} else {
		options.LogType = windows.LogTypeStdout
	}
	options.MaxTicks = *maxTicks

	// now start the emulator with the various options
	emu, err := windows.Load(flag.Arg(0), flag.Args()[1:], options)
	if err != nil {
		log.Fatal(err)
	}

	emu.Start()
}
