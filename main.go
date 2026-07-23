//go:generate bash -c "test -f vmlinux.h || bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
//go:generate go tool bpf2go -tags linux -cflags "-g -O2 -mcpu=v3" -target amd64 stalemount stalemount.c

package main

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const pin_path = "/sys/fs/bpf/stalemount/"

var (
	lsm_pin_path  = pin_path + "lsmopen"
	kput_pin_path = pin_path + "kput"
)

type mount_info struct {
	mnt_id     int
	open_count uint32
	blocked    uint32
}

func bpf_start() error {
	if err := os.MkdirAll(pin_path, 0700); err != nil {
		return fmt.Errorf("mkdir pin path: %w", err)
	}

	objs := &stalemountObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pin_path},
	}

	if err := loadStalemountObjects(objs, opts); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	lsm_link, err := link.AttachLSM(link.LSMOptions{Program: objs.Lsmopen})
	if err != nil {
		return fmt.Errorf("attach lsm: %w", err)
	}

	if err := lsm_link.Pin(lsm_pin_path); err != nil {
		lsm_link.Close()
		return fmt.Errorf("pin lsm link: %w", err)
	}
	lsm_link.Close()

	kput_link, err := link.AttachTracing(link.TracingOptions{Program: objs.Kput})
	if err != nil {
		return fmt.Errorf("attach fentry: %w", err)
	}

	if err := kput_link.Pin(kput_pin_path); err != nil {
		kput_link.Close()
		return fmt.Errorf("pin kput link: %w", err)
	}
	kput_link.Close()

	return nil
}

func bpf_stop() error {
	return os.RemoveAll(pin_path)
}

func bpf_is_running() bool {
	_, err := os.Stat(lsm_pin_path)
	return err == nil
}

func open_pinned_maps() (*ebpf.Map, *ebpf.Map, error) {
	active_opens, err := ebpf.LoadPinnedMap(pin_path+"stalemount_active_opens", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("load pinned active_opens: %w", err)
	}

	policies, err := ebpf.LoadPinnedMap(pin_path+"stalemount_policies", nil)
	if err != nil {
		active_opens.Close()
		return nil, nil, fmt.Errorf("load pinned policies: %w", err)
	}

	return active_opens, policies, nil
}

func map_add(active_opens *ebpf.Map, policies *ebpf.Map, mnt_id int) error {
	key := int32(mnt_id)

	var open_count uint32
	if err := active_opens.Lookup(key, &open_count); err != nil {
		var zero uint32
		key := int32(mnt_id)

		if err := active_opens.Put(key, zero); err != nil {
			return fmt.Errorf("put active_opens: %w", err)
		}

	} else if open_count > 0 {
		return fmt.Errorf("mnt_id %d has %d active opens, cannot block", mnt_id, open_count)
	}

	var one uint32 = 1
	if err := policies.Put(key, one); err != nil {
		return fmt.Errorf("set policy: %w", err)
	}

	return nil
}

func map_remove(policies *ebpf.Map, mnt_id int) error {
	if err := policies.Delete(int32(mnt_id)); err != nil {
		return fmt.Errorf("delete policies: %w", err)
	}

	return nil
}
func map_status(active_opens *ebpf.Map, policies *ebpf.Map, mnt_id int) (*mount_info, error) {
	key := int32(mnt_id)
	var open_count, policy uint32

	if err := active_opens.Lookup(key, &open_count); err != nil {
		return nil, fmt.Errorf("mnt_id %d not found: %w", mnt_id, err)
	}

	_ = policies.Lookup(key, &policy)

	return &mount_info{
		mnt_id:     mnt_id,
		open_count: open_count,
		blocked:    policy,
	}, nil
}

func map_list(active_opens *ebpf.Map, policies *ebpf.Map) ([]mount_info, error) {
	var results []mount_info
	var key int32
	var open_count uint32

	iter := active_opens.Iterate()
	for iter.Next(&key, &open_count) {
		var policy uint32
		_ = policies.Lookup(key, &policy)

		results = append(results, mount_info{
			mnt_id:     int(key),
			open_count: open_count,
			blocked:    policy,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate: %w", err)
	}

	return results, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: %s <command> [args]

commands:
	start              load and pin bpf programs
	stop               unpin and unload everything
	add <mnt_id>       track a mount id
	remove <mnt_id>    stop tracking a mount id
	status <mnt_id>    show status of a mount id
	list               list all tracked mount ids
`, os.Args[0])
	os.Exit(1)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func need_running() {
	if !bpf_is_running() {
		die("bpf not loaded, run 'start' first")
	}
}

func parse_mnt_id() int {
	if len(os.Args) < 3 {
		die("%s requires a mnt_id argument", os.Args[1])
	}

	mnt_id, err := strconv.Atoi(os.Args[2])
	if err != nil {
		die("invalid mnt_id %q: %v", os.Args[2], err)
	}

	return mnt_id
}

func print_mounts(mounts []mount_info) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "MNT_ID\tOPEN_COUNT\tBLOCKED")

	for _, m := range mounts {
		blocked := "no"
		if m.blocked != 0 {
			blocked = "yes"
		}
		fmt.Fprintf(w, "%d\t%d\t%s\n", m.mnt_id, m.open_count, blocked)
	}

	w.Flush()
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cmd := os.Args[1]

	switch cmd {
	case "start":
		do_start()
	case "stop":
		do_stop()
	case "add":
		do_add()
	case "remove":
		do_remove()
	case "status":
		do_status()
	case "list":
		do_list()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
	}
}

func do_start() {
	if bpf_is_running() {
		die("already running, stop first")
	}

	if err := bpf_start(); err != nil {
		die("start: %v", err)
	}

	fmt.Println("bpf programs loaded and pinned")
}

func do_stop() {
	need_running()

	if err := bpf_stop(); err != nil {
		die("stop: %v", err)
	}

	fmt.Println("bpf programs unloaded, pins removed")
}

func do_add() {
	need_running()
	mnt_id := parse_mnt_id()

	active_opens, policies, err := open_pinned_maps()
	if err != nil {
		die("%v", err)
	}
	defer active_opens.Close()
	defer policies.Close()

	if err := map_add(active_opens, policies, mnt_id); err != nil {
		die("add: %v", err)
	}

	fmt.Printf("mnt_id %d added\n", mnt_id)
}

func do_remove() {
	need_running()
	mnt_id := parse_mnt_id()

	active_opens, policies, err := open_pinned_maps()
	if err != nil {
		die("%v", err)
	}
	defer active_opens.Close()
	defer policies.Close()

	if err := map_remove(policies, mnt_id); err != nil {
		die("remove: %v", err)
	}

	fmt.Printf("mnt_id %d removed\n", mnt_id)
}

func do_status() {
	need_running()
	mnt_id := parse_mnt_id()

	active_opens, policies, err := open_pinned_maps()
	if err != nil {
		die("%v", err)
	}
	defer active_opens.Close()
	defer policies.Close()

	info, err := map_status(active_opens, policies, mnt_id)
	if err != nil {
		die("status: %v", err)
	}

	print_mounts([]mount_info{*info})
}

func do_list() {
	need_running()

	active_opens, policies, err := open_pinned_maps()
	if err != nil {
		die("%v", err)
	}
	defer active_opens.Close()
	defer policies.Close()

	mounts, err := map_list(active_opens, policies)
	if err != nil {
		die("list: %v", err)
	}

	if len(mounts) == 0 {
		fmt.Println("no mounts tracked")
		return
	}

	print_mounts(mounts)
}
