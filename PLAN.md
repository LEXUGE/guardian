# Guardian
Guardian is a sandbox tool based on gVisor used primarily for agentic coding. It's meant to be:
1. Simple yet effective in terms security boundary and architecture. No security theater.
2. Harness-agnostic: provides the basic features expected by mainstream tool like streaming output and relaying status code.

## Goal and Design
As of v1, the project primarily focuses on the network stack.

Since it's meant to be a sandbox that provides "computer-use" for LLMs, it should *eventually* have an interface (modeled after pi.dev) that asynchronously:
1. starts the process in container
2. streams output to the harness
3. relays exit code to the harness

For now being able to start a process (e.g. bash) and allow human to test out the sandboxing is enough.

gVisor natively supports filesystem binding and various modes like read-only, copy-on-write etc. Hence we don't need to worry about those nor do we need to implement an interface that exposes those functionalities now.

Our primary focus is on the network interface.

It involves:
1. untrusted guest which we assume may channel arbitrary bytestream through channels available.
2. a trusted proxy which enforces network policies like HTTPS termination, domain filtering, HTTP method filtering etc.

 The ultimate goal is to allow audited, strictly enforced HTTP and UDP connections with the untrusted guest while reducing the attack surface. In particular, since the untrusted guest may produce arbitrary byte stream, they should *not* be forwarded through the host's kernel network stack.

The design is therefore:
1. No virtual NIC for the guest. So no veth link into the container hence no network traffic into the host kernel stack.
2. The only channels are through Unix Domain Sockets with the host.
3. On Unix Domain Sockets, guest is supposed to send HTTP requests and our trusted proxy will act like a HTTP proxy server. This deliberately removes the TCP as the transport layer since we don't need the reliability it provides and the attack surface it exposes.
4. Also over UDS, we provide a simple UDP proxy.

Even though over UDS guests may emit arbitrary byte stream, it's easier and simpler to have a secure HTTP/UDP proxy server rather than a custom complicated TCP stack.

So in diagram it's

guest --UDS--> trusted HTTP proxy
      --UDS--> trusted UDP proxy

For now, let's keep the trusted proxies running unsandboxed on host. We can later lock them down for extra security.
