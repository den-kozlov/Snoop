unit Pcap;

interface

uses
  Windows, WinSock, Bpf;

// ----------------------------------------------------------------------------
// Constant Definition
// ----------------------------------------------------------------------------
const
  PCAP_VERSION_MAJOR = 2;
  PCAP_VERSION_MINOR = 4;
  PCAP_ERRBUF_SIZE = 256;
  PCAP_IF_LOOPBACK = $00000001;	{ interface is loopback }
  RPCAP_RMTAUTH_NULL = 0;
  RPCAP_RMTAUTH_PWD = 1;
  PCAP_OPENFLAG_PROMISCUOUS = 1;
  PCAP_OPENFLAG_SERVEROPEN_DP = 2;
  PCAP_OPENFLAG_UDP_DP = 4;

  MODE_CAPT = 0;
  MODE_STAT = 1;
  MODE_MON = 2;

// ----------------------------------------------------------------------------
// Type Definition
// ----------------------------------------------------------------------------
type
  ppcap_t = ^pcap_t;
  pcap_t = integer;

  pbpf_u_int32 = ^bpf_u_int32;
  bpf_u_int32 = integer; // gilgil temp 2003.07.20
  long = integer;
  u_int = LongWord;
  ppchar = ^pchar; // gilgil temp 2003.07.20

  ppcap_addr_t = ^pcap_addr_t;
  pcap_addr_t = packed record
	next: ppcap_addr_t;
	addr: PSockAddrIn; { address }
	netmask: PSockAddrIn; { netmask for that address }
	broadaddr: PSockAddrIn; { broadcast address for that address }
	dstaddr: PSockAddrIn; { P2P destination address for that address }
  end;

  ppcap_if_t = ^pcap_if_t;
  pppcap_if_t = ^ppcap_if_t;
  pcap_if_t = packed record
	next: ppcap_if_t;
	name: pchar;
	description: pchar;
	address : ppcap_addr_t;
	flags: bpf_u_int32;
  end;

  ppkt_header = ^pkt_header;
  pkt_header = integer; // gilgil temp 2003.07.20

  ppcap_rmtauth = ^pcap_rmtauth;
  pcap_rmtauth = packed record
	type_: integer;
	username: pchar;
	password: pchar;
  end;

  timeval = packed record
	tv_sec: long;
	tv_usec: long;
  end;

  ppcap_pkthdr = ^pcap_pkthdr;
  pcap_pkthdr = packed record
	ts: timeval;
	caplen: bpf_u_int32;
	len :bpf_u_int32
  end;

  ppcap_dumper_t = ^pcap_dumper_t;
  pcap_dumper_t = integer; // gilgil temp 2003.07.26

  pcap_handler = procedure(p: pchar; header: ppkt_header; data: pchar); cdecl;

// ----------------------------------------------------------------------------
// Function Definition
// ----------------------------------------------------------------------------
function pcap_findalldevs(alldevs: pppcap_if_t ; errbuf : pchar): integer; cdecl;
function pcap_findalldevs_ex(source: pchar; auth: ppcap_rmtauth; alldevs: ppcap_if_t; errbuf: pchar): integer; cdecl;
procedure pcap_freealldevs(alldevs: ppcap_if_t); cdecl;
function pcap_open_live(device: pchar; snaplen: integer; promisc: integer; to_ms: integer; ebuf: pchar): ppcap_t; cdecl;
function pcap_open(source: pchar; snaplen: integer; flags: integer; read_timeout: integer; auth: ppcap_rmtauth; errbuf: pchar): ppcap_t; cdecl;
procedure pcap_close(p: ppcap_t); cdecl;
function pcap_loop(p: ppcap_t; cnt: integer; ppcap_handler: pointer; user: pchar): integer; cdecl;
function pcap_next_ex(p: ppcap_t; pkt_header: ppcap_pkthdr; pkt_data: ppchar): integer; cdecl;
function pcap_lookupnet(device: pchar; netp: pbpf_u_int32; maskp: pbpf_u_int32; errbuf: pchar): integer; cdecl;
function pcap_compile(p: ppcap_t; fp: pbpf_program; str: pchar; optimize: integer; netmask: bpf_u_int32): integer; cdecl;
function pcap_setfilter(p: ppcap_t; fp: pbpf_program): integer; cdecl;
function pcap_geterr(p: ppcap_t): pchar; cdecl;
function pcap_dump_open(p: ppcap_t; fname: pchar): ppcap_dumper_t; cdecl;
procedure pcap_dump(p: ppcap_dumper_t; h: ppcap_pkthdr; sp: pchar); cdecl;
procedure pcap_dump_close(p: ppcap_dumper_t); cdecl;
function pcap_sendpacket(p: ppcap_t; buf: pchar; size: integer): integer; cdecl;
function pcap_setmode(p: ppcap_t; mode: integer): integer; cdecl;

implementation

function pcap_findalldevs; external 'wpcap.dll' name 'pcap_findalldevs';
function pcap_findalldevs_ex; external 'wpcap.dll' name 'pcap_findalldevs_ex';
procedure pcap_freealldevs; external 'wpcap.dll' name 'pcap_freealldevs';
function pcap_open_live; external 'wpcap.dll' name 'pcap_open_live';
function pcap_open; external 'wpcap.dll' name 'pcap_open';
procedure pcap_close; external 'wpcap.dll' name 'pcap_close';
function pcap_loop; external 'wpcap.dll' name 'pcap_loop';
function pcap_next_ex; external 'wpcap.dll' name 'pcap_next_ex';
function pcap_lookupnet; external 'wpcap.dll' name 'pcap_lookupnet';
function pcap_compile; external 'wpcap.dll' name 'pcap_compile';
function pcap_setfilter; external 'wpcap.dll' name 'pcap_setfilter';
function pcap_geterr; external 'wpcap.dll' name 'pcap_geterr';
function pcap_dump_open; external 'wpcap.dll' name 'pcap_dump_open';
procedure pcap_dump; external 'wpcap.dll' name 'pcap_dump';
procedure pcap_dump_close; external 'wpcap.dll' name 'pcap_dump_close';
function pcap_sendpacket; external 'wpcap.dll' name 'pcap_sendpacket';
function pcap_setmode; external 'wpcap.dll' name 'pcap_setmode';

end.
