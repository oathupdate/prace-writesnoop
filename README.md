# Ptrace writesnoop

Use `ptrace` to watch for any `write` and `read` syscalls that a process or it's child
process(es) make.

First, find a processes threads and it's child processes and their threads. A processes
threads can be found by listing the files from `/proc/<pid>/task/*`, each new file indicates
a thread pid. The processes parent pid is found from `/proc/<pid>/stat` file.

Next, we ptrace `seize` and `interrupt` each process, and then call `wait(-1)` which will
wait for any of the traced processes state to change. A state is changed before and after each
syscall. When a state changes, we get its register contents and check to see if there is a
`write` or `read` syscall being made.

NOTE: This is very invasive, ptrace will take control of eahc process and make each process
a child process of this running program. For a non-invasive approach look at a
[bpf-writesnoop](https://github.com/vishen/bpf-writesnoop).

## Running

```
$ cat t.go
package main

import (
        "fmt"
        "time"
)

func main() {
        for i := 0; ; i++ {
                fmt.Printf("%d) hello, go\n", i)
                time.Sleep(time.Second)
        }
}
$ go run t.go

# Aattach to the `go run t.go` process, and all it's threads and child processes.
$ sudo ./ptrace-writesnoop 2015
{2015 1940 (go) 83 [2015 2016 2017 2018 2019 2020 2021 2022 2023 2024 2025 2026 2062 2063 2064 2065 2066 2067]}
[{2099 2015 (t) 83 [2099 2100 2101 2102 2103]}]
attached 2015
attached 2016
attached 2017
attached 2018
attached 2019
attached 2020
attached 2021
attached 2022
attached 2023
attached 2024
attached 2025
attached 2026
attached 2062
attached 2063
attached 2064
attached 2065
attached 2066
attached 2067
attached 2099
attached 2100
attached 2101
attached 2102
attached 2103
2099) [OUT] "38) hello, go\n"
2099) [OUT] "38) hello, go\n"
2099) [OUT] "39) hello, go\n"
2099) [OUT] "39) hello, go\n"
2099) [OUT] "40) hello, go\n"
2099) [OUT] "40) hello, go\n"
2099) [OUT] "41) hello, go\n"
2099) [OUT] "41) hello, go\n"
2099) [OUT] "42) hello, go\n"
2099) [OUT] "42) hello, go\n"
2099) [OUT] "43) hello, go\n"
2099) [OUT] "43) hello, go\n"
2099) [OUT] "44) hello, go\n"
2099) [OUT] "44) hello, go\n"
```

