# eBPF Introduction

# Overview

> eBPF is a revolutionary technology with origins in the Linux kernel that can run sandboxed programs in a privileged context such as the operating system kernel.
> 

![](../images/aws-cni.png)

Basically it’s a tool to run user programs inside the Linux kernel.

## Example

1. create a `hello_world.c` file
    
    ```c
    int hello_world(void *ctx)
    {
        bpf_trace_printk("Hello, World!");
        return 0;
    }
    ```
    
2. create a `hello_world.py` script (see golang example [here](https://github.com/cilium/ebpf/tree/master/examples/kprobe))
    
    ```python
    #!/usr/bin/env python3
    from bcc import BPF
    
    b = BPF(src_file="hello_world.c")
    b.attach_kprobe(event=b.get_syscall_fnname("socket"), fn_name="hello_world")
    b.trace_fields()
    ```
    
    - `BPF(src_file="hello_world.c")` loads the source file
    - `event=b.get_syscall_fnname("socket")` executes the function(`fn_name="hello_world"` ) for [socket system call](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
    - `b.trace_fields()` prints the output
3. run the program
    
    ```bash
    sudo python3 hello_world.py
    ```
    

## Linux kernel implementation

BPF program is eventually executed [here](https://elixir.bootlin.com/linux/v5.14/source/include/linux/filter.h#L602)

### [BPF hooks](https://docs.cilium.io/en/stable/network/ebpf/intro/)

- XDP
    
     [Filter RX packets](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21) right after device driver handler
    
    <aside>
    💡 It takes effect before TC ingress and packet taps which means you won’t see anything with `tcpdump` if the packet is dropped by [XDP filter](https://elixir.bootlin.com/linux/v5.14/source/net/core/dev.c#L4868).
    
    </aside>
    
- TC ingress
    
    BPF program attached to the [TC ingress](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21) hook will be [executed](https://elixir.bootlin.com/linux/v5.14/source/net/sched/cls_bpf.c#L80)
    
    ```bash
    tc filter add dev eth0 ingress bpf obj "hello_world.o"
    ```
    
- TC egress
    
    BPF program attached to the [TC egress](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21) hook will be executed
    
    ```bash
    tc filter add dev eth0 egress bpf obj "hello_world.o"
    ```
    
- CGroup ingress(`BPF_CGROUP_RUN_PROG_INET_INGRESS`)
    - TCP handshake [step3](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
        
        Server filters the ACK segment before establishing the TCP connection(change ).
        
    - [Packet processing](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21) after 3way handshake
- CGroup egress(`BPF_CGROUP_RUN_PROG_INET_EGRESS`)
    
    Right after [postrouting](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21) chain filter
    
- Socket operation
    - [tcp connect](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
        
        client initiates an tcp connection
        
    - [socket listen](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
        
        server starts to listen on a socket
        
    - [tcp state change](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
        
        every time when the tcp connection state changes
        
    - [packet transmit](https://www.notion.so/IPv6-deep-dive-b08343fd7be84f9080fa12acd8c311f0?pvs=21)
        
        before the packet is handed to IP layer
        

### Datapath



# Architecture

![Screenshot 2023-06-12 at 14.00.21.png](eBPF%20Introduction%20e3b6e2ba1ad14ad898bb942a5d6a0478/Screenshot_2023-06-12_at_14.00.21.png)

## [Compiler](https://ebpf.io/what-is-ebpf/#how-are-ebpf-programs-written)

[LLVM/Clang](https://llvm.org/)  is used to compile the C code(e.g. `hello_world.c`) into eBPF [bytecode](https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/bpf.h#L71)

```c
struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

## [**Loader**](https://ebpf.io/what-is-ebpf/#loader--verification-architecture)

The program is loaded into the Linux kernel by [system call](https://elixir.bootlin.com/linux/v5.14/source/kernel/bpf/syscall.c#L4427), user eBPF bytecode is copied user space to kernel space into [`bpf_prog`](https://elixir.bootlin.com/linux/v5.14/source/kernel/bpf/syscall.c#L2134) .

```c
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr)
{
		enum bpf_prog_type type = attr->prog_type;
		struct bpf_prog *prog, *dst_prog = NULL;
		...
		prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
		...
		prog->aux->attach_btf = attach_btf;
		prog->aux->attach_btf_id = attr->attach_btf_id;
		...
		prog->aux->user = get_current_user();
		prog->len = attr->insn_cnt;
		if (copy_from_bpfptr(prog->insns,
			     make_bpfptr(attr->insns, uattr.is_kernel),
			     bpf_prog_insn_size(prog)) != 0)
				goto free_prog_sec;
		...
}
```

[`bpf_prog`](https://elixir.bootlin.com/linux/v5.14/source/include/linux/filter.h#L565) represents the eBPF program ([BPF program is eventually executed [here](https://elixir.bootlin.com/linux/v5.14/source/include/linux/filter.h#L602)](https://www.notion.so/BPF-program-is-eventually-executed-here-f862b46cae17403687d9bf37caab114b?pvs=21))

```c
struct bpf_prog {
	enum bpf_prog_type	type;		/* Type of BPF program */
	...
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	struct sock_filter	insns[0];
	struct bpf_insn		insnsi[];
};
```

## [Verifier](https://ebpf.io/what-is-ebpf/#verification)

> The verification step ensures that the eBPF program is safe to run.
> 

[**`bpf_check`](https://elixir.bootlin.com/linux/v5.14/C/ident/bpf_check)** is the verifier which checks the assembly commands in the eBPF program.

```c
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr)
{
		...
		/* run eBPF verifier */
		err = bpf_check(&prog, attr, uattr);
		...
}

int bpf_check(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr)
{
	ret = check_subprogs(env);
	...	
	ret = check_cfg(env);
	...
}
```

## [JIT](https://ebpf.io/what-is-ebpf/#jit-compilation)

[`jit_subprogs`](https://elixir.bootlin.com/linux/v5.14/C/ident/jit_subprogs) is used to translate the eBPF bytecode into the native code.

```c
int bpf_check(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr)
{
	...	
	ret = check_cfg(env);
	...
	if (ret == 0)
		ret = fixup_call_args(env);
}
```

## Hook Attaching

[attach system call](https://elixir.bootlin.com/linux/v5.14/source/kernel/bpf/syscall.c#L4478) is used to attach the eBPF program to a hook.

```c
static int bpf_prog_attach(const union bpf_attr *attr)
{
	enum bpf_prog_type ptype;
	...
	switch (ptype) {
	...
	case BPF_PROG_TYPE_CGROUP_SKB:
		ret = cgroup_bpf_prog_attach(attr, ptype, prog);
		...
	}
	...
}
```

e.g. [`BPF_CGROUP_INET_INGRESS`](https://elixir.bootlin.com/linux/v5.14/source/include/linux/bpf-cgroup.h#L230) is attached to [CGroup ingress(`BPF_CGROUP_RUN_PROG_INET_INGRESS`)](https://www.notion.so/CGroup-ingress-BPF_CGROUP_RUN_PROG_INET_INGRESS-6381b669f4f24aedb7da59ca6dc5eec0?pvs=21) 

```c
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled(BPF_CGROUP_INET_INGRESS))		      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    BPF_CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})
```

## [Maps](https://ebpf.io/what-is-ebpf/#maps)

Data transfer/share between user space and kernel space.

> eBPF maps can be accessed from [eBPF programs](https://github.com/cilium/ebpf/blob/master/examples/cgroup_skb/cgroup_skb.c) as well as from applications in user space via a [system call](https://elixir.bootlin.com/linux/v5.14/source/kernel/bpf/syscall.c#L4453).
> 

```c
struct bpf_map_def SEC("maps") pkt_count = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};
```

data is copied between user space and kernel space.

```c
// read
static int map_lookup_elem(union bpf_attr *attr)
{
	...
	key = __bpf_copy_key(ukey, map->key_size);
	...
	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	err = bpf_map_copy_value(map, key, value, attr->flags);
	...
	if (copy_to_user(uvalue, value, value_size) != 0)
		goto free_value;
	...
}

// write
static int map_update_elem(union bpf_attr *attr, bpfptr_t uattr)
{
	...
	key = ___bpf_copy_key(ukey, map->key_size);
	...
	if (copy_from_bpfptr(value, uvalue, value_size) != 0)
		goto free_value;
	err = bpf_map_update_value(map, f, key, value, attr->flags);
...
}
```
