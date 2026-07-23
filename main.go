//go:generate bash -c "test -f vmlinux.h || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go tool bpf2go -tags linux -cflags -mcpu=v3 -target amd64 stalemount stalemount.c
package main

import (
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pinpath = "/sys/fs/bpf/stalemount/"

func main() {
	os.MkdirAll(pinpath, os.ModeDir)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	obj := &stalemountObjects{}
	if err := loadStalemountObjects(obj, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinpath}}); err != nil {
		panic(err)
	}
	defer obj.Close()

	lsm, err := link.AttachLSM(link.LSMOptions{Program: obj.Lsmopen})
	if err != nil {
		obj.Close()
		panic(err)
	}
	defer lsm.Close()

	kput, err := link.AttachTracing(link.TracingOptions{Program: obj.Kput})
	if err != nil {
		obj.Close()
		lsm.Close()
		panic(err)
	}
	defer kput.Close()

	println("waiting for you signal")
	<-ch

	os.RemoveAll(pinpath)
}
