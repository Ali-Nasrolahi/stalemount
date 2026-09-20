# Stale Mount

**Stale Mount** is an eBPF-based Linux tool for controlling access to filesystem mounts and tracking
their active users.

It allows a mount to be placed into a **blocked state**, where new file opens are denied while
existing file handles continue to operate normally. At the same time, Stale Mount tracks active
opens for each mount, allowing userspace to determine when a mount is no longer being actively used.

This enables a controlled workflow for filesystem maintenance: stop new workloads from entering a
mount, wait for existing users to finish, and then safely perform operations such as unmounting,
modifying, or replacing the underlying filesystem.

## Purpose

Consider a filesystem mounted at a location that is actively being used by other processes. You may
need to unmount it temporarily to perform maintenance, modify the underlying storage, or carry out
other operations.

Unmounting immediately can disrupt processes that are already working with the mount. On the other
hand, simply waiting does not prevent new processes from starting work while you wait.

Stale Mount provides a way to **drain a mount**:

* New file opens can be blocked.
* Existing file handles are allowed to continue.
* Active opens are tracked for the mount.
* Userspace can monitor the mount until its active usage reaches zero.
* Once no active opens remain, the mount can be safely taken out of service.

The goal is therefore not to forcibly terminate access, but to provide a controlled transition from
an **actively used mount** to a **quiescent mount** that is ready for maintenance.

## How It Works

The system consists of a small userspace controller and eBPF programs running in the kernel:

1. The controller identifies a target mount using its kernel mount ID.
2. The eBPF LSM program intercepts file open operations.
3. If the file belongs to a blocked mount, the open operation is rejected.
4. Existing file handles continue to operate normally.
5. A tracing program tracks file releases so the controller can monitor active opens on each mount.
6. The Go controller manages the policies and exposes the current state through a CLI.

## Architecture

### Linux Kernel

The kernel-side component uses eBPF to implement two pieces of functionality:

* **LSM hook**: controls new file open operations based on the mount ID.
* **Tracing hook**: tracks the lifecycle of active file handles.

The programs communicate through BPF maps containing mount policies and active-open counts.

### Userspace Controller

A Go-based CLI loads and manages the eBPF programs and maintains their state through pinned BPF
objects.

Because the state is kept in pinned BPF maps, individual CLI invocations do not need to maintain a
long-running daemon.

## Policy Model

Policies are associated with Linux mount IDs.

A mount can be in one of two states:

* **Allowed**: new file opens proceed normally.
* **Blocked**: new file opens on the mount are rejected.

The policy applies only to **new opens**. It does not terminate processes, invalidate existing file
descriptors, or forcibly unmount the filesystem.

## Usage

Start the eBPF programs:

```bash
sudo ./stalemount start
```

Inspect a mount:

```bash
sudo ./stalemount status <mnt_id>
```

Block a mount:

```bash
sudo ./stalemount add <mnt_id>
```

Remove the blocking policy:

```bash
sudo ./stalemount remove <mnt_id>
```

List tracked mounts:

```bash
sudo ./stalemount list
```

Stop and clean up the eBPF programs:

```bash
sudo ./stalemount stop
```

A mount can be inspected using standard Linux tools such as:

```bash
findmnt -o TARGET,MNT_ID
```

## Current Limitations

* The tool operates on Linux mount IDs and does not provide path-based policies.
* Blocking new opens does not terminate existing users or force an unmount.
* The implementation requires a kernel with the necessary eBPF LSM and tracing support.
* BPF LSM must be enabled and included in the system's active LSM configuration.
