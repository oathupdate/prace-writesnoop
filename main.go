// Copyright © 2018 Jonathan Pentecost <penetcostjonathan@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
	"syscall"
)

type Proc struct {
	Pid  int
	Ppid int

	Command string
	State   byte

	ThreadPids []int
}

type TraceProc struct {
	Pid           int
}

func NewTraceProc(pid int) TraceProc {
	return TraceProc{Pid: pid})
}

func (p TraceProc) attach() error {
	pid := p.Pid
	PTRACE_SEIZE := 0x4206
	options := syscall.PTRACE_O_TRACESYSGOOD | syscall.PTRACE_O_TRACEEXEC | syscall.PTRACE_O_TRACEEXIT
	if _, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(PTRACE_SEIZE), uintptr(pid), 0, uintptr(options), 0, 0); errNo != 0 {
		return fmt.Errorf("%d can't seize ptrace: %v\n", pid, errNo)
	}

	PTRACE_INTERRUPT := 0x4207
	if _, _, errNo := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(PTRACE_INTERRUPT), uintptr(pid), 0, 0, 0, 0); errNo != 0 {
		return fmt.Errorf("%d can't interuppt ptrace: %v\n", pid, errNo)
	}

	return nil
}

func loadProcs() []Proc {
	files, err := ioutil.ReadDir("/proc")
	if err != nil {
		log.Fatal(err)
	}

	procs := []Proc{}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		// - To find a processes thread: /proc/<pid>/task/* - all the folders are threads
		// - To find a processes children, must search all /proc/<pid> for the /proc/<pid>/stat
		//   where the parent id is that of pid
		/*
			/proc/[pid]/cmdline -> contains the full path of command being run
			/proc/[pid]/stat
				Status information about the process.  This is used by ps(1).
				It is defined in the kernel source file fs/proc/array.c.

				The fields, in order, with their proper scanf(3) format speci‐
				fiers, are listed below.  Whether or not certain of these
				fields display valid information is governed by a ptrace
				access mode PTRACE_MODE_READ_FSCREDS | PTRACE_MODE_NOAUDIT
				check (refer to ptrace(2)).  If the check denies access, then
				the field value is displayed as 0.  The affected fields are
				indicated with the marking [PT].

				(1) pid  %d
				  		The process ID.
				(2) comm  %s
				  		The filename of the executable, in parentheses.
				  		This is visible whether or not the executable is
				  		swapped out.
				(3) state  %c
				  		One of the following characters, indicating process
				  		state:
				  		R  Running
				  		S  Sleeping in an interruptible wait
				  		D  Waiting in uninterruptible disk sleep
				  		Z  Zombie
				  		T  Stopped (on a signal) or (before Linux 2.6.33)
				  		   trace stopped
				  		t  Tracing stop (Linux 2.6.33 onward)
				  		W  Paging (only before Linux 2.6.0)
				  		X  Dead (from Linux 2.6.0 onward)
				  		x  Dead (Linux 2.6.33 to 3.13 only)
				  		K  Wakekill (Linux 2.6.33 to 3.13 only)
				  		W  Waking (Linux 2.6.33 to 3.13 only)
				  		P  Parked (Linux 3.9 to 3.13 only)
				(4) ppid  %d
							The PID of the parent of this process.
		*/

		statFileBytes, err := ioutil.ReadFile("/proc/" + f.Name() + "/stat")
		if err != nil {
			continue
		}
		fields := bytes.SplitN(statFileBytes, []byte{' '}, 5)
		ppid, err := strconv.Atoi(string(fields[3]))
		if err != nil {
			continue
		}

		p := Proc{
			Pid:        pid,
			Ppid:       ppid,
			Command:    string(fields[1]),
			State:      fields[2][0],
			ThreadPids: []int{},
		}

		threads, err := ioutil.ReadDir("/proc/" + f.Name() + "/task")
		if err != nil {
			log.Fatal(err)
		}
		for _, t := range threads {
			threadPid, err := strconv.Atoi(t.Name())
			if err != nil {
				continue
			}
			p.ThreadPids = append(p.ThreadPids, threadPid)

		}
		procs = append(procs, p)
	}

	return procs
}

func init() {
	runtime.LockOSThread()
}

func main() {
	flag.Parse()
	pid, _ := strconv.Atoi(flag.Args()[0])
	run(pid)
}

func run(pid int) {
	var proc Proc
	children := []Proc{}
	for _, p := range loadProcs() {
		if p.Pid == pid {
			proc = p
		} else if p.Ppid == pid {
			children = append(children, p)
		}
	}

	fmt.Println(proc)
	fmt.Println(children)

	pidsToWatch := []TraceProc{}
	pidsToWatch = append(pidsToWatch, NewTraceProc(proc.Pid))

	// Watching process threads
	for _, t := range proc.ThreadPids {
		if t == proc.Pid {
			continue
		}
		pidsToWatch = append(pidsToWatch, NewTraceProc(t))
	}

	// Watching process children
	for _, c := range children {
		pidsToWatch = append(pidsToWatch, NewTraceProc(c.Pid))
		// Watching process children threads
		for _, t := range c.ThreadPids {
			if t == c.Pid {
				continue
			}
			pidsToWatch = append(pidsToWatch, NewTraceProc(t))
		}
	}

	// Seize and start initial interrupt ptrace, this will ptrace seize
	// each process / child/ thread, and run ptrace interrupt on each.
	for _, pid := range pidsToWatch {
		pid.attach()
		fmt.Printf("attached %d\n", pid.Pid)
	}

	for {
		ws := syscall.WaitStatus(0)
		options := 0x40000000
		// Wait for any change to any of the tracee processes.
		// -1 will wait for any traced process.
		pid, err := syscall.Wait4(-1, &ws, options, nil)
		if err != nil {
			fmt.Printf("%d can't wait ptrace: %v\n", pid, err)
			continue
		}

		// Get the traced process current register
		var regs syscall.PtraceRegs
		if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
			fmt.Printf("%d can't get regs ptrace: %v\n", pid, err)
			continue
		}

		switch orax := regs.Orig_rax; orax {
		case 1:
			// Syscall write
			out := make([]byte, regs.Rdx)
			if _, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), out); err != nil {
				fmt.Printf("Error PtracePeekData(...): %s\n", err)
			}
			fmt.Printf("%d) [OUT] %q\n", pid, string(out))
		case 0:
			// Syscall read
			out := make([]byte, regs.Rdx)
			if _, err := syscall.PtracePeekData(pid, uintptr(regs.Rsi), out); err != nil {
				fmt.Printf("Error PtracePeekData(...): %s\n", err)
			}
			fmt.Printf("%d) [IN] %q\n", pid, string(out))
		}

		// Because we catch any signals meant for the traced process,
		// we need to send it on to the process.
		sig := 0
		if ss := ws.StopSignal(); ss > 0 && ss < 31 {
			sig = int(ss)
		}

		if err := syscall.PtraceSyscall(pid, sig); err != nil {
			panic(err)
		}
	}
}
