# The protocol as tqftpserv handles it

This describes what `tqftpserv.c` and `translate.c` do, not what TFTP or the
RFCs say. Where the two differ, the code is described. Numbers are in bytes
unless stated.

## Transport

- QRTR datagrams. The daemon publishes service 4096, version 1, instance 0,
  and receives requests on that socket, the service socket.
- Every accepted transfer gets a new QRTR socket, connected to the client's
  node and port. All later packets of the transfer go to and come from that
  socket.
- An error before a transfer exists is sent from a new socket connected to
  the client, which is closed straight after.
- Sockets come from libqrtr's `qrtr_open()`: blocking, with a 1 s receive
  timeout that does not matter as reads follow `select()`. Sends have no
  timeout. The daemon is one thread with one `select()` loop.
- A send waits for QRTR flow control: once a remote port has 10 DATA
  packets it has not confirmed, the kernel waits without a time limit
  (`qrtr_tx_wait()`), whatever the socket's send timeout. A remote that
  stops confirming holds up the whole daemon until its processor goes away.
- All 16-bit fields are big endian.

## Packets on the service socket

The daemon reads at most 4095 bytes, a longer datagram is cut there. A packet
under 2 bytes is dropped.

| Sender port | Opcode | What happens |
|---|---|---|
| control port (`QRTR_PORT_CTRL`) | any | Control message, see below |
| other | 1 RRQ | Read request |
| other | 2 WRQ | Write request, or delete with the `unlink` option |
| other | 5 ERROR | With at least 4 bytes, logged. Nothing else |
| other | anything else | Logged as unhandled. No reply |

### Control messages

- Only taken from the local node. From any other node they are logged and
  dropped.
- Decoded by libqrtr. A packet that does not decode (under 20 bytes) is
  dropped.
- BYE (3): every transfer of the node named in the packet ends.
- DEL_CLIENT (6): every transfer of the node and port named in the packet ends.
- Any other type is ignored.
- Ending a transfer closes its socket and file and frees it. The client is
  not told.

## Requests

```
| opcode (2) | filename | 0 | mode | 0 | option | 0 | value | 0 | ... |
```

Checks, in order. A failed check sends the error shown and stops:

| Step | RRQ | WRQ |
|---|---|---|
| filename not ended by NUL in the packet | dropped, no reply | dropped, no reply |
| mode missing or not ended by NUL | dropped, no reply | dropped, no reply |
| mode not `octet` (any case) | 4 "Only octet mode supported" | same |
| path check fails (see Paths) | 2 "Access violation" | same |
| options do not parse | 8 "Option negotiation failed" | same |
| `unlink` option | 8 "Option negotiation failed" | delete, see Delete |
| blksize × wsize over 1 MiB | (not checked) | 8 "Option negotiation failed" |
| seek over 16 MiB | (not checked) | 3 "File too large" |
| no session slot (see Limits) | 0 "Too many transfers" | same |
| socket cannot be opened or connected | no reply | no reply |
| file does not open | 1 "file not found" | 3 "Too many files" if the file count is full, else 2 "Access violation" |
| seek fails | (no seek here) | 0 "Seek failed" |
| tsize asked and the size cannot be read | 0 "Cannot determine file size" | (not done) |
| memory | 0 "Resources temporarily unavailable" | 0 "Resources temporary unavailable" |
| WRQ without seek: truncate fails | | 0 "Truncate failed" |

An RRQ opens its socket before the file, so its open and size errors come
from the transfer's socket. The other errors before a transfer exists come
from a short-lived socket. Either way the client sees a new port.

The WRQ file is opened before the socket. If a later step fails for a file the
WRQ created, the file stays, empty.

### Accepted requests

- If anything follows the mode, the reply is an OACK. Otherwise an RRQ gets
  DATA block 1 and a WRQ gets ACK block 0.
- A WRQ without `seek` truncates the file to 0 once it is accepted. With
  `seek`, writing starts at that offset and the rest of the file is kept.

### Options

Pairs of NUL-ended strings after the mode. A name without a value, or any
string not ended by NUL in the packet, fails the whole request.

- Names are compared case-sensitively.
- Values are read by `strtoll()` in base 10: leading white space and a sign
  are accepted, anything after the digits fails, and an empty value reads
  as 0.
- An option given twice takes its last value.
- An unknown option is logged and ignored, but still makes the reply an OACK.

| Option | Accepted | Default | Use |
|---|---|---|---|
| blksize | 8 to 65464 | 512 | DATA payload size |
| timeoutms | 1 to 255000 | 1000 | Echoed only. The daemon has no retransmit timer |
| tsize | 0 to the largest ssize_t (2^31 - 1 on 32-bit builds) | absent | RRQ: replaced by the file size in the OACK. WRQ: echoed as sent |
| rsize | 1 to 104857600 | 0 (none) | RRQ: bytes to read. WRQ: echoed only |
| wsize | 1 to 256 | 1 | Blocks per window |
| seek | 0 to the largest off_t (2^31 - 1 on 32-bit builds) | absent | Start offset. WRQ: at most 16 MiB |
| unlink | any value, WRQ only | absent | Delete the file. In an RRQ it fails the request |

### OACK

Options in this order: `blksize`, `timeoutms`, `tsize` (if asked), `wsize`,
`rsize` (if not 0), `seek` (if asked). `blksize`, `timeoutms` and `wsize` are
always there, even when not asked for. The OACK of a delete carries only
`blksize`, `timeoutms` and `unlink` with the value `0`. An OACK is at most 512
bytes.

## Reading (RRQ)

The client sends ACKs on the transfer's socket. The daemon reads at most 127
bytes of each packet.

| Packet from the client | What happens |
|---|---|
| under 4 bytes | transfer ends, no reply |
| ERROR | transfer ends, no reply. Code 9 is logged as end of transfer |
| not ACK | 4 "Expected ACK opcode", transfer ends |
| ACK n with n × blksize > rsize | transfer ends, no reply |
| other ACK n | DATA blocks n+1 to n+wsize, see below |

- DATA block k holds the file from offset seek + (k-1) × blksize, up to
  blksize bytes. The block number on the wire is k modulo 65536. Offsets
  come from the 16-bit ACK number, so a transfer reaches at most 65535 + 256
  blocks.
- When k × blksize passes rsize, block k holds rsize modulo blksize bytes,
  or a full block if that is 0, and the window stops after it. If the file
  has fewer bytes there than rsize modulo blksize, nothing is sent and the
  window stops.
- No state is kept of what was sent. Any ACK, older or newer, is answered
  from its own number.
- A read error sends 0 "Read error" and stops the window. The transfer stays.

## Writing (WRQ)

The client sends DATA on the transfer's socket. The daemon reads at most
blksize + 4 bytes of each packet, so a longer one is cut to a full block.

| Packet from the client | What happens |
|---|---|
| under 4 bytes | 4 "Malformed packet", transfer ends |
| not DATA | 4 "Expected DATA opcode", transfer ends |
| DATA with another block number than expected | 4 "Block number out of sequence", transfer ends |
| DATA with the expected number | taken into the window |

- The first block expected is 1, then each next one. After 65535 comes 0.
- Taken blocks are kept in memory. The window is written to the file, at the
  current offset, and ACKed with the number of the last block when that block
  number is a multiple of wsize or its payload is shorter than blksize.
- Before each write the budgets are checked (see Limits). Over budget, or a
  failed write, sends 3 "Disk full or write error" and ends the transfer.
- A block shorter than blksize, after its write and ACK, ends the transfer.

## Delete

A WRQ with the `unlink` option, whatever its value.

- Only paths under `/readwrite/`. Anything else gets 2 "Access violation".
- The path is walked as for writing, without following links. The last name
  is removed with `unlinkat()`: a link is removed itself, a directory is
  refused.
- Missing file: 1 "file not found". Other failures: 2 "Access violation".
- Success: OACK as above. No transfer, no session slot.

## Paths

### The check

`sanitize_path()` runs on every requested path:

- one leading `/` is allowed
- an empty component (`//` anywhere after the first character) is refused
- a `..` component is refused
- `.`, a trailing `/` and any other byte are allowed

### Translation

The first matching prefix wins:

| Prefix | Looked up as |
|---|---|
| `/readonly/firmware/image/` | firmware, the rest of the path |
| `/readonly/firmware/modem_pr` (no slash) | firmware, `modem_pr` and the rest |
| `/readwrite/` | readwrite, the rest of the path |
| `/readonly/vendor/firmware_mnt/image/` | firmware, the rest of the path |
| `/readonly/vendor/firmware/` | firmware, the rest of the path |
| anything else | not found |

Firmware lookup of a name R:

1. For each entry of `/sys/class/remoteproc`, in directory order, read its
   `firmware` file and take the directory part D of its value.
2. Try, in order: the `firmware_class` path from sysfs + `/D/R` (if that path
   is set), then the firmware base + `updates/D/R`, then the firmware base +
   `D/R`. The firmware base is `/vendor/firmware/` on Android and
   `/lib/firmware/` elsewhere.
3. For each try, the file itself, then with `.xz`, then with `.zst`. The
   Android build has no decompressor, so the compressed names never open.
4. The first that opens wins. Links in the firmware folders are followed.
   The file is opened read-only whatever the request.

Readwrite lookup of a name R:

- The folder is `/data/vendor/tmp/tqftpserv` on Android and
  `/var/lib/tqftpserv` elsewhere. It is created (mode 0700) if missing.
- R is walked from the folder one component at a time. A component that is a
  link, is not a directory, is empty or is over 255 bytes fails. The last
  name is opened without following a link.
- A read opens the file read-only. A write opens it write-only and creates it
  (mode 0600) if missing, if the file count allows.

## Limits

| Limit | Value | Where |
|---|---|---|
| transfers in all | 64 | RRQ and WRQ, before opening anything |
| transfers per node | 32 | same |
| blocks per window | 256 | option parsing |
| write window | blksize × wsize ≤ 1 MiB | WRQ |
| rsize | 100 MiB | option parsing |
| file size | 16 MiB | WRQ seek, and each write |
| readwrite bytes | 64 MiB | each write that grows a file |
| readwrite entries | 256 | creating a file |
| idle | 120 s | every turn of the loop |

- Bytes and entries count every level of the readwrite folder, without
  following links. A file counts at its full size, sparse or not. Every
  entry counts: files, folders and links. A folder more than 8 levels deep
  makes the folder count as full.
- A write that stays within the file's current size is always allowed.
- A transfer is idle when nothing came from its client for 120 s. Packets
  from anyone else do not count. While a transfer exists, `select()` waits at
  most 10 s, so an idle transfer ends within about 130 s. With no transfer
  there is no timer. The clock is `CLOCK_MONOTONIC`, which stops while the
  phone is suspended.

## Clients and nodes going away

A transfer ends on: its end in the tables above, idle, a BYE for its node, or
a DEL_CLIENT for its node and port. Its socket and file are closed and its
memory freed. The client is told only where a table above lists an error.

## Packets from someone else

On a transfer's socket, a packet from any other node or port than the
transfer's client is dropped. It gets no reply, changes nothing and does not
count as activity.

## Oddities

1. A read without `rsize` sends one block only: any ACK above 0 ends it.
2. When rsize is a multiple of blksize, the block after rsize is sent in full.
3. Past the end of the file, but within rsize, a window is filled with empty
   DATA blocks.
4. ACKs are never checked against what was sent.
5. Option names are case-sensitive and an empty value reads as 0.
6. `wsize`, `blksize` and `timeoutms` are echoed even when not asked for.
7. Any RRQ open failure, also access or path errors, is "file not found".
8. A WRQ for a firmware path opens the file read-only. Without `seek` it gets
   "Truncate failed", with `seek` the first write fails.
9. A WRQ that creates a file and then fails leaves the file, empty.
10. Two transfers may use the same file. A WRQ without seek truncates it under
    a running read or write, and a delete removes it under them. A transfer
    whose file was deleted keeps writing to it, and those bytes no longer
    count against the readwrite budget.
11. `/readonly/firmware/modem_pr` matches without a slash, so
    `/readonly/firmware/modem_prX` is looked up as `modem_prX`.
12. A directory can be opened for reading. Its reads fail with "Read error".
13. A DATA block out of sequence ends the write. There is no rewind.
14. After block 65535 a write expects block 0, and the window ends at the
    next multiple of wsize, so that window can be shorter.
15. The daemon never retransmits on its own and ignores `timeoutms`.
16. Requests that cannot get a socket get no reply.
17. A control message names the node it ends in its payload, not by its
    sender, which must be the local node's control port.
