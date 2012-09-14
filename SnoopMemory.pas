unit SnoopMemory;

interface

uses
  SysUtils, Snoop,
  SnoopTrace; // gilgil temp 2003.08.19

type
  PSnoopMemoryNode = ^TSnoopMemoryNode;
  PInteger = ^Integer;
  TSnoopMemoryNode = packed record
	PacketHeader: PCAP_PKTHDR;
	Next: PSnoopMemoryNode;
	Data: array [0 .. 0] of Char;
  end;
  TSnoopMemory = class
  public
	HeaderNode: PSnoopMemoryNode;
  protected
	TailNode: PSnoopMemoryNode;
	function GetEmpty: Boolean;
  public
	constructor Create;
	destructor Destroy; override;
	procedure Clear;
	function Enqueue(PacketHeader: PPCAP_PKTHDR; Data: PChar): PSnoopMemoryNode;
	function GetNext(HeaderNode: PSnoopMemoryNode): PSnoopMemoryNode;
	procedure Next;
  public
	property IsEmpty: Boolean read GetEmpty;
  end;

implementation

function TSnoopMemory.GetEmpty: Boolean;
begin
	Result := HeaderNode = nil;
end;

constructor TSnoopMemory.Create;
begin
	HeaderNode := nil;
	TailNode := nil;
end;

destructor TSnoopMemory.Destroy;
begin
	Clear;
end;

procedure TSnoopMemory.Clear;
var
	TempNode: PSnoopMemoryNode;
begin
	while HeaderNode <> nil do
	begin
		TempNode := HeaderNode^.Next;
		FreeMem(HeaderNode);
		HeaderNode := TempNode;
	end;
	TailNode := nil;
end;

function TSnoopMemory.Enqueue(PacketHeader: PPCAP_PKTHDR; Data: PChar): PSnoopMemoryNode;
var
	DataLength: Integer;
	TotalLength: Integer;
	Node: PSnoopMemoryNode;
begin
	DataLength := PacketHeader.len;
	TotalLength := sizeof(TSnoopMemoryNode) + DataLength;
	GetMem(Node, TotalLength);
	if Node = nil then
	begin
		Result := nil;
		SnoopGTrace('[SnoopMemory.pas] Node=nil', []);
		exit;
	end;
	// Process PacketHeader
	StrMove(PChar(@Node^.PacketHeader), PChar(PacketHeader), sizeof(PCAP_PKTHDR));
	// Process Next
	Node^.Next := nil;
	// Process Data
	StrMove(@Node^.Data, Data, DataLength);
	// Process SnoopMemory's HeaderNode and TailNode
	if HeaderNode = nil then // if First Enqueue
		HeaderNode := Node;
	if TailNode <> nil then // if TailNode Exists
		TailNode^.Next := Node;
	TailNode := Node;
	Result := Node;
end;

function TSnoopMemory.GetNext(HeaderNode: PSnoopMemoryNode): PSnoopMemoryNode;
begin
	Result := nil;
	if HeaderNode <> nil then
		Result := HeaderNode^.Next;
end;

procedure TSnoopMemory.Next;
var
	TempNode: PSnoopMemoryNode;
begin
	TempNode := HeaderNode^.Next;
	FreeMem(HeaderNode);
	HeaderNode := TempNode;
end;

end.


