package oomprocesser

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/cilium/ebpf"
)

type OOMEvent struct {
	Pid        uint32 `json:"pid"`
	FComm      string `json:"fcomm"`
	CgroupID   uint32 `json:"cgroupID"`
	CgroupPath string `json:"cgroup_path"`
	UStackSize int    `json:"ustack_size"`
	UStack     string `json:"ustack"`
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	eBPFprogram := GetEBPFProg()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeOomKillProcess *ebpf.ProgramSpec `ebpf:"kprobe_oom_kill_process"`
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	KprobeMap *ebpf.MapSpec `ebpf:"oom_map"`
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	OomMap *ebpf.Map `ebpf:"oom_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.OomMap,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeOomKillProcess *ebpf.Program `ebpf:"kprobe_oom_kill_process"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeOomKillProcess,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/oomkillprocesser.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
