package oomprocesser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog"
)

var (
	oomKillProcessFN = "oom_kill_process"
)

func WatchOOM(ch chan<- *OOMEvent) {
	eBPFprogram := GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		klog.Errorf("failed to load collection spec: %v", err)
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	prog := coll.DetachProgram("kprobe_oom_kill_process")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_oom_kill_process")
		log.Fatal(errors.New(msg))
	}

	kp, err := link.Kprobe(oomKillProcessFN, prog, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	oomMap := coll.DetachMap("oom_map")
	for {
		var (
			key   uint32
			event []byte
		)
		for oomMap.Iterate().Next(&key, &event) {
			oomEvent := DecodeMapItem(event)
			klog.Infof("oom event: %+v", oomEvent)
			if err := oomMap.Delete(key); err != nil {
				log.Fatalf("deleting map: %v", err)
			}
			ch <- oomEvent
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func printCgroup(cgroupid uint32) {
	buildCmd := exec.Command("/bin/bash", "-c", fmt.Sprintf("grep -i '%d' -R /sys/fs/cgroup/", cgroupid))
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	buildCmd.Run()
}

func DecodeMapItem(e []byte) *OOMEvent {
	m := new(OOMEvent)
	m.Pid = binary.LittleEndian.Uint32(e[0:4])
	m.FComm = string(e[4:20])
	m.CgroupID = binary.LittleEndian.Uint32(e[20:24])
	//m.CgroupPath = string(e[24:153])
	m.UStackSize = int(e[24])
	m.UStack = string(e[25 : 25+m.UStackSize])
	//var maxDepth = 10
	//if m.UStackSize < maxDepth {
	//	maxDepth = m.UStackSize
	//}
	//for i := 0; i < maxDepth; i++ {
	//	m.UStack += string(e[25+i*4 : 29+i*4])
	//}
	//m.UStack = string(e[25:65])
	return m
}
