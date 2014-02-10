#import tracecmd
import struct


# Default amount of padding to add to the left of strings being printed
# to the trace output
PAD = 65

# Print a string to the trace buffer output with reasonable alignment.
# Really should only be used for lines of a multi-line print after the
# first.
def trace_puts(trace_seq, s):
    trace_seq.puts("%*s %s" % (PAD, "", s))

# Version of trace_puts which adds extra padding
def trace_puts_pad(trace_seq, pad, s):
    trace_seq.puts("%*s %s" % (PAD + pad, "", s))


# Pretty-print a bitfield. Takes as an argument a bitfield (bf) and a list
# of descriptions. The elements of the description list is another list
# with the following items (in order):
#
#  - Start bit for the field
#  - Number of bits for the field
#  - Short description (i.e. name) of the field
#  - Long description of the field
def print_bitfield(trace_seq, pad, bf, descs):
    for (start, length, name, description, conv) in descs:
        field = (bf >> start) & ((1 << length) - 1)
        if conv != None:
            trace_puts_pad(trace_seq, pad, "%-15s %8s (%s)\n" % (name, conv(field), description))
        else:
            trace_puts_pad(trace_seq, pad, "%-15s %#8x (%s)\n" % (name, field, description))

def dump_hex(trace_seq, data):
    i = 0
    s = ''
    for i in range(len(data)):
        if (i % 16) == 0:
            trace_seq.puts("%04x " % i)
	if data[i] > 31 and data[i] < 127:
            s = s + ('%c' % data[i])
	else:
            s = s + '.'
        trace_seq.puts(" %02x" % (data[i]))
        if (i % 16) == 15:
            trace_seq.puts("  %s\n%*s" % (s, PAD, ""))
            s = ''
    if len(s) > 0:
	if len(s) < 16:
	    trace_seq.puts("%*s" % ((16 - len(s)) * 3, ""))
        trace_seq.puts("  %s" % s)
    if (i % 16) != 15:
        trace_seq.puts("\n")


def hexdump_event_handler(pevent, trace_seq, event):
    addr = long(event['addr'])
    data_len = long(event['len'])
    fmt = pevent.file_endian + str(data_len) + 'B'
    data = struct.unpack(fmt, str(event['hdata'].data))
    trace_seq.puts("address: 0x%X length: %d (0x%X)\n%*s" % (addr, data_len, data_len, PAD, ""))
    dump_hex(trace_seq, data)

def dump_macstate_data(tseq, data):
    hdl = int(data[0])
    trace_puts(tseq, "    handle %d (idx %d)\n" % (hdl, hdl & 0x1F))

def dump_request_data(tseq, data):
    hdl = int(data[1])
    cnt = int(data[0])
    bmp = int(data[2])
    trace_puts(tseq, "    handle %d (idx %d)\n" % (hdl, hdl & 0x1F))
    trace_puts(tseq, "    count %d bmp %x\n" % (cnt, bmp))

def txs2str(val):
    labels = [ 'discard', 'd11-suppr', 'fw-suppr', 'tossed' ]
    return labels[val]

def dump_txs_data(tseq, data):
    txs_fields = [
        [ 31, 1, 'generation', 'life-cycle info', None ],
        [ 27, 4, 'flags', 'status value', txs2str ],
        [ 24, 3, 'fifo', 'fifo number', None ],
        [ 8, 16, 'hslot', 'hanger slot index', None ],
        [ 0, 24, 'pktid', 'packet tag', None ]
    ]
    status = int(data[0])
    status |= (int(data[1]) << 8)
    status |= (int(data[2]) << 16)
    status |= (int(data[3]) << 24)
    print_bitfield(tseq, 5, status, txs_fields)

def tagflag2str(val):
    labels = [ 'N/A', 'host', 'N/A', 'fw-req' ]
    return labels[val]

def dump_pkttag_data(tseq, data):
    tag_fields = [
        [ 31, 1, 'generation', 'life-cycle info', None ],
        [ 27, 4, 'flags', 'status value', tagflag2str ],
        [ 24, 3, 'fifo', 'fifo number', None ],
        [ 8, 16, 'hslot', 'hanger slot index', None ],
        [ 0,  8, 'freerun', 'sequence counter', None ]
    ]
    pkttag = int(data[0])
    pkttag |= (int(data[1]) << 8)
    pkttag |= (int(data[2]) << 16)
    pkttag |= (int(data[3]) << 24)
    print_bitfield(tseq, 5, pkttag, tag_fields)

def dump_credit_data(tseq, data):
    vals = ( int(data[0]), int(data[1]), int(data[2]),
    	     int(data[3]), int(data[4]), int(data[5]) )
    trace_puts(tseq, "    BK: %d BE: %d VO: %d VI: %d BC/MC: %d ATIM: %d\n" % vals)

def dump_macdesc_data(tseq, data):
    hdl = int(data[0])
    ifidx = int(data[1])
    trace_puts(tseq, "    handle %d (idx %d)\n" % (hdl, hdl & 0x1F))
    trace_puts(tseq, "    ifidx  %d mac %02X:%02X:%02X:%02X:%02X:%02X\n" % ( ifidx,
    	      int(data[2]), int(data[3]), int(data[4]),
    	      int(data[5]), int(data[6]), int(data[7])))

def dump_iface_data(tseq, data):
    trace_puts(tseq, "    ifidx %d\n" % int(data[0]))

def dump_tim_data(tseq, data):
    tim_fields = [
        [ 0, 1, 'BK', 'background', None ],
        [ 1, 1, 'BE', 'best-effort', None ],
        [ 2, 1, 'VI', 'video', None ],
        [ 3, 1, 'VO', 'voice', None ]
    ]
    hdl = int(data[0])
    tim = int(data[1])
    trace_puts(tseq, "    handle %d (idx %d)\n" % (hdl, hdl & 0x1F))
    print_bitfield(tseq, 5, tim, tim_fields)

def dump_reorder_data(tseq, data):
    reorder_flags = [
        [ 0, 1, 'delete', 'delete flow', None ],
        [ 1, 1, 'flush', 'flush all', None ],
        [ 2, 1, 'curvld', 'curidx valid', None ],
        [ 3, 1, 'expvld', 'expidx valid', None ],
        [ 4, 1, 'hole', 'new hole', None ]
    ]
    fid=int(data[0])
    maxidx=int(data[2])
    flags=int(data[4])
    curidx=int(data[6])
    expidx=int(data[8])
    trace_puts(tseq, "    fid %d maxidx %d curidx %d expidx %d\n" % (fid, maxidx, curidx, expidx))
    print_bitfield(tseq, 5, flags, reorder_flags)

tlv_info = {
    1:  ("MAC_OPEN", 1, dump_macstate_data),
    2:  ("MAC_CLOSE", 1, dump_macstate_data),
    3:  ("MAC_REQUEST_CREDIT", 2, dump_request_data),
    4:  ("TXSTATUS", 4, dump_txs_data),
    5:  ("PKTTAG", 4, dump_pkttag_data),
    6:  ("MACDESC_ADD", 8, dump_macdesc_data),
    7:  ("MACDESC_DEL", 8, dump_macdesc_data),
    8:  ("RSSI", 1, None),
    9:  ("INTERFACE_OPEN", 1, dump_iface_data),
    10: ("INTERFACE_CLOSE", 1, dump_iface_data),
    11: ("FIFO_CREDITBACK", 6, dump_credit_data),
    12: ("PENDING_TRAFFIC_BMP", 2, dump_tim_data),
    13: ("MAC_REQUEST_PACKET", 3, dump_request_data),
    14: ("HOST_REORDER_RXPKTS", 10, None),
    18: ("TRANS_ID", 6, None),
    19: ("COMP_TXSTATUS", 1, None)
}

def tlv_name(type):
    if not type in tlv_info:
        return "UNKNOWN"

    (n, l, fn) = tlv_info[type]
    return n

def tlv_len(type):
    if not type in tlv_info:
        return -1

    (n, l, fn) = tlv_info[type]
    return l

def tlv_parse(type):
    if not type in tlv_info:
        return None

    (n, l, fn) = tlv_info[type]
    return fn

def bdchdr_dump_signal(tseq, type, len, signal):
    vals = (tlv_name(type), type, len, tlv_len(type))
    trace_puts(tseq, "  TLV: %s (%d) len %d (%d):\n" % vals)
    fn = tlv_parse(type)
    if fn != None:
    	    fn(tseq, signal)
    return len+2

def bdchdr_dump_signals(tseq, signals, siglen):
    if siglen <= 2:
        return
    pos = 0
    while pos < siglen:
        type = int(signals[pos])
        if type != 255:
            length = int(signals[pos+1])
            pos += bdchdr_dump_signal(tseq, type, length, signals[pos+2:])
        else:
            pos += 1

def bdchdr_event_handler(pevent, trace_seq, event):
    flags = long(event['flags'])
    prio = long(event['prio'])
    flags2 = long(event['flags2'])
    trace_seq.puts("BDC(%x:%d:%x):\n" % (flags, prio, flags2))
    siglen = long(event['siglen'])
    fmt = pevent.file_endian + str(siglen) + 'B'
    signals = struct.unpack(fmt, str(event['signal'].data))
    bdchdr_dump_signals(trace_seq, signals, siglen)

sdpcm_channels = [
	"CONTROL",
	"EVENT",
	"DATA",
	"GLOM"
]

dir2str = [
	"RX",
	"TX",
	"TXG"
]

def sdpcm_event_handler(pevent, trace_seq, event):
    dirnum = int(event['dir'])
    data_bytes = 12
    swhdr_start = 4
    # depending on dir data is 12 or 20 bytes
    if dirnum == 2:
        data_bytes = 20
        swhdr_start += 8
    fmt = pevent.file_endian + ('%dB' % data_bytes)
    hdr = struct.unpack(fmt, str(event['hdr'].data))
    length = long(event['len'])
    try:
        direction = dir2str[dirnum]
    except IndexError:
        direction = "INV"

    trace_seq.puts("%s length %d (0x%X), seq %d (0x%X):\n" % (direction, length, length, hdr[swhdr_start], hdr[swhdr_start]))
    channum = int(hdr[swhdr_start+1]) & 0xF
    flags = (int(hdr[swhdr_start+1]) & 0xF0) >> 4
    try:
        channel = sdpcm_channels[channum]
    except IndexError:
	channel = "INVALID"
    if dirnum == 2:
        glomlen = int(hdr[4]) | (int(hdr[5]) << 8)
        tailpad = int(hdr[10]) | (int(hdr[11]) << 8)
        trace_puts(trace_seq, "hw ext. header:\n")
        trace_puts(trace_seq, " glomlen: %d\n" % glomlen)
        trace_puts(trace_seq, " lastfrm: %d\n" % int(hdr[7]))
        trace_puts(trace_seq, " tailpad: %d\n" % tailpad)
    trace_puts(trace_seq, "sw header:\n")
    trace_puts(trace_seq, " channel: %s [%d]\n" % (channel, channum))
    trace_puts(trace_seq, " flags:   %d\n" % flags)
    trace_puts(trace_seq, " nextlen: %d\n" % int(hdr[swhdr_start+2]))
    trace_puts(trace_seq, " doffset: %d\n" % int(hdr[swhdr_start+3]))
    trace_puts(trace_seq, " fcmask:  0x%X\n" % int(hdr[swhdr_start+4]))
    trace_puts(trace_seq, " window:  %d\n" % int(hdr[swhdr_start+5]))
    trace_puts(trace_seq, " version: %d\n" % int(hdr[swhdr_start+6]))

DMP_DESC_STATE_IDLE = 0
DMP_DESC_STATE_COMP = 1
DMP_DESC_STATE_ADDR = 2

dmp_state = DMP_DESC_STATE_IDLE

DMP_DESC_TYPE_COMP = 1
DMP_DESC_TYPE_MPORT = 3
DMP_DESC_TYPE_ADDR = 5
DMP_DESC_TYPE_EMPTY = 0
DMP_DESC_TYPE_EOT = 15

dmp_comp_a_fields = [
    [ 20, 12, 'mfg', 'designer', None ],
    [ 8, 12, 'id', 'part number', None ],
    [ 4, 4, 'class', 'core class', None ],
]

dmp_comp_b_fields = [
    [ 24, 8, 'rev', 'core revision', None ],
    [ 19, 5, 'nsw', 'slave wrappers', None ],
    [ 14, 5, 'nmw', 'master wrappers', None ],
    [ 9, 5, 'nsp', 'slave ports', None ],
    [ 4, 5, 'nmp', 'master ports', None ],
]

dmp_master_fields = [
    [ 8, 8, 'uid', 'unique master id', None ],
    [ 4, 4, 'port', 'master port number', None ],
]

def get_dmp_address(val):
    return '%08X' % (val << 12)

def dmp_slave_type(val):
    slaves = [ 'SLAVE', 'BRIDGE', 'SLVWRAP', 'MSTWRAP' ]
    return slaves[val]

def dmp_size_type(val):
    sizes = [ '4K', '8K', '16K', 'CUSTOM' ]
    return sizes[val]

dmp_address_fields = [
    [ 12, 20, 'addr', 'base address', get_dmp_address ],
    [ 8, 4, 'port', 'slave port number', None ],
    [ 6, 2, 'type', 'slave type', dmp_slave_type ],
    [ 4, 2, 'size', 'address region size', dmp_size_type ],
    [ 3, 1, 'gt32', 'address over 32 bit', None ],
]

dmp_size_fields = [
    [ 12, 20, 'size', 'address region size', get_dmp_address ],
    [ 3, 1, 'gt32', 'size over 32 bit', None ],
]

def dmpdesc_idle_handler(ts, dtype, val):
    state = DMP_DESC_STATE_IDLE
    if dtype == DMP_DESC_TYPE_COMP:
	ts.puts("Component: 0x%08X\n" % val)
	print_bitfield(ts, 5, val, dmp_comp_a_fields)
	state = DMP_DESC_STATE_COMP
    elif dtype == DMP_DESC_TYPE_MPORT:
	ts.puts("Master:    0x%08X\n" % val)
        print_bitfield(ts, 5, val, dmp_master_fields)
    elif dtype & 7 == DMP_DESC_TYPE_ADDR:
	ts.puts("Slave:     0x%08X\n" % val)
        print_bitfield(ts, 5, val, dmp_address_fields)
        sztype = (val & 0x00000030) >> 4
        if sztype == 3:
            state = DMP_DESC_STATE_ADDR
    elif dtype == DMP_DESC_TYPE_EOT:
        ts.puts("DMP EROM END\n")
    elif dtype == DMP_DESC_TYPE_EMPTY:
	pass
    else:
	ts.puts("unexpected desc: %d data 0x%08X\n" % (dtype, val))
    return state

def dmpdesc_comp_handler(ts, dtype, val):
    state = DMP_DESC_STATE_COMP
    if dtype == DMP_DESC_TYPE_COMP:
	ts.puts("Component: 0x%08X\n" % val)
	print_bitfield(ts, 5, val, dmp_comp_b_fields)
	state = DMP_DESC_STATE_IDLE
    elif dtype == DMP_DESC_TYPE_EOT:
        ts.puts("DMP EROM END\n")
	state = DMP_DESC_STATE_IDLE
    elif dtype == DMP_DESC_TYPE_EMPTY:
	pass
    else:
	ts.puts("unexpected desc: %d data 0x%08X\n" % (dtype, val))
    return state

def dmpdesc_addr_handler(ts, dtype, val):
    state = DMP_DESC_STATE_ADDR
    if dtype & 7 == 0:
	ts.puts("Size:      0x%08X\n" % val)
        print_bitfield(ts, 5, val, dmp_size_fields)
        state = DMP_DESC_STATE_IDLE
    elif dtype == DMP_DESC_TYPE_EOT:
        ts.puts("DMP EROM END\n")
	state = DMP_DESC_STATE_IDLE
    elif dtype == DMP_DESC_TYPE_EMPTY:
	pass
    else:
	ts.puts("unexpected desc: %d data 0x%08X\n" % (dtype, val))
    return state

dmp_desc_handlers = [
    dmpdesc_idle_handler, dmpdesc_comp_handler,
    dmpdesc_addr_handler
]

def dmpdesc_event_handler(pevent, traceseq, event):
    global dmp_state
    desc = int(event['desc'])
    dtype = desc & 0xF
    dmp_state = dmp_desc_handlers[dmp_state](traceseq, dtype, desc)

def register(pevent):
    pevent.register_event_handler("brcmfmac", "brcmf_hexdump",
            lambda *args: hexdump_event_handler(pevent, *args))
    pevent.register_event_handler("brcmfmac", "brcmf_bdchdr",
            lambda *args: bdchdr_event_handler(pevent, *args))
    pevent.register_event_handler("brcmfmac", "brcmf_sdpcm_hdr",
            lambda *args: sdpcm_event_handler(pevent, *args))
    pevent.register_event_handler("brcmfmac", "brcmf_dmp_desc",
            lambda *args: dmpdesc_event_handler(pevent, *args))

class TestSequencer:
	def puts(self, s):
		sys.stdout.write(s)

if __name__ == "__main__":
	import sys
	ts = TestSequencer()
	print('testing: tsig1')
	tsig1 = struct.unpack( '17B', '\x04\x04\x01\x07\x00\x9C\x02\x01\x21\x03\x03\x01\x21\x1F\x01\x01\x21')
	bdchdr_dump_signals(ts, tsig1, len(tsig1))
	print('testing: tsig2')
	tsig2 = struct.unpack( '10B', '\x05\x04\x01\x00\x02\xA7\x0C\x02\x41\x09')
	bdchdr_dump_signals(ts, tsig2, len(tsig2))
	print('testing: tsig3')
	tsig3 = struct.unpack( '30B', '\x0B\x06\x00\x02\x00\x00\x00\x00\x06\x08\x41\x01\x00\x90\x4c\x12\x02\x7e\xff\xff\x07\x08\x41\x01\x00\x90\x4c\x12\x02\x7e')
	bdchdr_dump_signals(ts, tsig3, len(tsig3))
