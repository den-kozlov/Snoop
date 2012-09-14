unit bpf;

interface

uses
  WinSock;

type
  pbpf_program = ^bpf_program;
  bpf_program = packed record
	bf_len: u_int;
	bf_insns: pchar; // gilgil temp 2003.07.20
  end;

implementation

end.
