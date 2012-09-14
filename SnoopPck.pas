{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit SnoopPck;

interface

uses
  Bpf, IpExport, IpHlpApi, IpIfConst, IpRtrMib, IpTypes, Pcap, Snoop, 
  SnoopMemory, SnoopTrace, LazarusPackageIntf;

implementation

procedure Register;
begin
  RegisterUnit('Snoop', @Snoop.Register);
end;

initialization
  RegisterPackage('SnoopPck', @Register);
end.
