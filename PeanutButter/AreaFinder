uses
   Math, Environment, Strings;

/////////////////////////////////////////////////////////////////////////////
// Any System Message Area Index Code
// ==========================================================================
// Designed to use 5 byte hex naming schema - or 1 to 1,048,576 areas.
// Uses 1 control file "MSGAREAS.LST" which contains the Key (message area #)
// and visible human name for the area. This information is self managed so
// you can add an area with a gap in the key number, or you can allow this
// code to return the next available key number, or combinations of both.
// This design can also be applied to file areas. Note the logic applied is
// for any environment to put all the message or file areas into the same
// folder, allowing for 1 million per folder structure - thus allowing your
// system to virtually handle unlimited message areas or file areas.
// Everything has been designed to Add, Find, Load, Save, etc. in under one
// second so it can be used in real-time mission critical apps. QuickSort
// is provided for maintenace - like repacking after deletion, in testing it
// can take over 1 minute to restore the areas list. To avoid this ridiculous
// amount of time, you should use AddArea and DeleteArea, as they adjust the
// sorted list in real-time. You should always call save, as we have a built
// in dirty list flag - and Save will only execute when the list has changed.
/////////////////////////////////////////////////////////////////////////////

Type
   OneMeg=$00000..$FFFFF;
   //////////////////////////////////////////////////////////////////////////
   // Sort by Name not Key - Key is part of the FILENAME
   //////////////////////////////////////////////////////////////////////////
   AreaKey=Packed Record
      Key:OneMeg;                // 5 bytes 1,048,576 $00000..$FFFFF
      Name:ShortString;          // 80 characters enough for NNTP groups?
      lname:ShortString;
   End;

Var
   Areas:Array of AreaKey;
   NextArea:OneMeg;
   NeedToSave:Boolean;

procedure QuickSort(var A:array of AreaKey;iLo,iHi:Integer);
var
   _Lo,_Hi:Integer;
   _Mid:AnsiString;
   T:AreaKey;

begin
   _Lo:=iLo;
   _Hi:=iHi;
   _Mid:=A[(_Lo+_Hi) div 2].lName;
   repeat
      while A[_Lo].lName<_Mid do Inc(_Lo);
      while A[_Hi].lName>_Mid do Dec(_Hi);
      if _Lo<=_Hi then begin
         T:=A[_Lo];
         A[_Lo]:=A[_Hi];
         A[_Hi]:=T;
         Inc(_Lo);
         Dec(_Hi);
      end;
   until _Lo>_Hi;
   if _Hi>iLo then QuickSort(A,iLo,_Hi);
   if _Lo<iHi then QuickSort(A,_Lo,iHi);
end;

function findArea(AreaName:String):OneMeg;
var
   ATL,A1,A2,A:OneMeg;
   C:Longint;

label
   a9510, a9520, a9530, a9540;

begin
   Result:=0;
   ATL:=Length(Areas);
   If ATL<1 then Exit;
   A1:=1;
   A2:=ATL-1;
a9510:
   If A1>A2 then goto a9530;
   A:=(A1+A2) div 2;
// DEBUG: Writeln('A: ',A,' ',Areas[A].Name,' ',CompareText(AreaName,Areas[A].Name));
   If A<2 then goto a9530;
   C:=CompareStr(AreaName,Areas[A].lName);
   If C=0 then begin
      Result:=A;
      Exit;
   End
   Else If C<0 then A2:=A-1
   Else A1:=A+1;
   Goto a9510;
a9530:
   A:=2;
a9540:
   If (Areas[A].lName=AreaName) then Result:=A
   else If A<>ATL-1 then
      If (Areas[ATL-1].lName=AreaName) then Result:=ATL-1;
End;

function nextAreaKey:OneMeg;
Var
   Bits:PByte;
   I,Blk,BitMemSize:Longint;
   Bit:Byte;

Begin
   Result:=0;
   BitMemSize:=Ceil(high(OneMeg) div 8);
   GetMem(Bits, BitMemSize);
// TRACK:
   For I:=1 to Length(Areas) do begin
      Bit:=Areas[I-1].Key mod 8;
      Blk:=Trunc(Areas[I-1].Key / 8);
      Set8Bit(Bits[Blk]^,Bit,True);
   End;
// FIND:
   For I:=0 to BitMemSize do begin
      Bit:=(I mod 8);
      Blk:=Trunc(I / 8);
      If (Blk<>0) and (Bit<>0) and not Get8Bit(Bits[Blk]^, Bit) then begin
         Result:=((Blk*8)+Bit);
         Break;
      End;
   End;
   FreeMem(Bits, BitMemSize);
End;

function addArea(AreaName:ShortString):Boolean;
var
   tmpan:ShortString;
   AreaCtr:OneMeg;

begin
   tmpan:=Lowercase(AreaName);
   AreaCtr:=Length(Areas);
   If FindArea(tmpan)=0 then begin
      If AreaCtr>0 then begin
         If Areas[0].lName=tmpan then Result:=False
         else begin
            SetLength(Areas,Length(Areas)+1); // expand the list
            AreaCtr:=AreaCtr-1; // adjust from length to last
            While Areas[AreaCtr].lName>tmpan do begin
               Areas[AreaCtr+1]:=Areas[AreaCtr];
               AreaCtr:=AreaCtr-1;
            End;
            Areas[AreaCtr+1].Key:=NextAreaKey;
            Areas[AreaCtr+1].Name:=AreaName;
            Areas[AreaCtr+1].lName:=tmpan;
         End;
      End
      Else Begin
         SetLength(Areas,1);
         Areas[0].Key:=1; //NextAreaKey;
         Areas[0].Name:=AreaName;
         Areas[0].lName:=tmpan;
      End;
      NeedToSave:=True;
      Result:=True;
   end
   else Result:=False;
End;

function delArea(AreaName:ShortString):Boolean;
var
   tmpan:ShortString;

begin
   tmpan:=Lowercase(AreaName);
   Result:=False;
   For var Loop:=1 to Length(Areas) do
      If Areas[Loop-1].lName=tmpan then begin
         For var Loop2:=Loop to Length(Areas)-1 do
            Areas[Loop2-1]:=Areas[Loop2];
         Result:=True;
         NeedToSave:=True;
         SetLength(Areas,Length(Areas)-1);
      End;
end;

function delAreaByKey(Key:OneMeg):Boolean;
begin
   Result:=False;
   For var Loop:=1 to Length(Areas) do
      If Areas[Loop-1].Key=Key then begin
         For var Loop2:=Loop to Length(Areas)-1 do
            Areas[Loop2-1]:=Areas[Loop2];
         Result:=True;
         NeedToSave:=True;
         SetLength(Areas,Length(Areas)-1);
      End;
end;

procedure loadAreas(CTLFile:String='./MSGAREAS.LST');
var
   BFH:File;
   Tmp:AreaKey;
   Len:Byte;
   Nw:LargeInt;
   AreaCtr:OneMeg;

begin
   AssignFile(BFH, CTLFile);
   If FileExists(CTLFile) then begin
      Reset(BFH,1);
      BlockRead(BFH,AreaCtr,5,Nw);
      SetLength(Areas,AreaCtr);
      AreaCtr:=0;
      While not EndOfFile(BFH) do begin
         BlockRead(BFH,Tmp.Key,5,Nw);
         BlockRead(BFH,Len,1,Nw);
         SetLength(Tmp.Name,Len);
         BlockRead(BFH,Tmp.Name[1],Len,Nw);
         Tmp.lName:=Lowercase(tmp.Name);
         Areas[AreaCtr]:=Tmp;
         AreaCtr:=AreaCtr+1;
      End;
   End
   else Begin
      Rewrite(BFH,1);
      AreaCtr:=0;
      BlockWrite(BFH,AreaCtr,5,Nw);
   End;
   CloseFile(BFH);
end;

procedure saveAreas(CTLFile:String='./MSGAREAS.LST');
var
   BFH:File;
   Ws:String;
   Len:Byte;
   Nw:LargeInt;
   AreaCtr:OneMeg;

begin
   if not NeedToSave then Exit;
//   QuickSort(Areas, 0, Length(Areas)-1);
   AssignFile(BFH, CTLFile);
   Rewrite(BFH,1);
   AreaCtr:=Length(Areas);
   BlockWrite(BFH,AreaCtr,5,Nw);
   For var I:=1 to Length(Areas) do begin
      Len:=Length(Areas[I-1].Name);
      SetLength(Ws,Len+6);
      Move(Areas[I-1].Key,Ws[1],5);
      Move(Char(Len),Ws[6],1);
      Move(Areas[I-1].Name[1],Ws[7],Len);
      BlockWrite(BFH,Ws[1],Len+6,Nw);
   End;
   CloseFile(BFH);
end;

begin
(*
Writeln('Allocate: ',Timestamp);
   SetLength(Areas,100000);
Writeln('Populate: ',Timestamp);
   For var Loop:=1 to 100000 do begin
      Areas[Loop-1].Key:=Loop;
      Areas[Loop-1].Name:='AREA'+IntToStr(Loop);
      Areas[Loop-1].lName:=lowercase(Areas[Loop-1].Name);
   End;
Writeln('SortArea: ',Timestamp);
   QuickSort(Areas, 0, Length(Areas)-1);
   NeedToSave:=True;
*)
Writeln('LoadArea: ',Timestamp);
   loadAreas;
Writeln('FindArea: ',Timestamp);
   Writeln('Record=',findArea('area'));
   Writeln('Record=',findArea('area5432'));
   Writeln('Record=',findArea('area9999'));
   Writeln('Record=',findArea('zarea5432'));
   If findArea('zarea5432')>0 then DelArea('zarea5432');
Writeln('NextArea: ',Timestamp);
   NextArea:=NextAreaKey;
   Writeln('Next Key=',NextArea);
Writeln('Add Area? ',AddArea('ZAREA5432'));
Writeln('SaveArea: ',Timestamp);
   saveAreas;
Writeln('Finished: ',Timestamp);
end.
