{$S-}
uses
   hashes, compressions, environment;

/////////////////////////////////////////////////////////////////////////////
// KNOWN DIFFERENCES:
// ==========================================================================
// Squish contains settings for maximum messages, minimum messages, etc.
// * PB this is not relative to the message - that is your external tools
//   settings MSG From, To, Subject are 36, 36, 72 bytes
// * PB this is limited of 1 to 255 bytes, by using an in-stream length byte
//   PKT/FIDO in general - network addressing is in the header
// * PB this information for *any* network can be stored a ^A (#1) kludge
//   tokens Hudson - uses 255 byte strings for the message body
// * PB uses an unsigned 64bit Frame (18,446,744,073,709,551,615 bytes or 18
//   Exabytes) JAM - more flexible for string lengths
// * PB took it further and the body blocks can be optionally compressioned
//   using LH6
/////////////////////////////////////////////////////////////////////////////

type
/////////////////////////////////////////////////////////////////////////////
// ma = Message Attribute
// na = Net Attribute
// in = Internet Attribute
// fa = Future Attribute
/////////////////////////////////////////////////////////////////////////////
   MessageHdrBits = (maDeleted, maUnmoved, maIsNetMail, maIsPrivate,
      maReceived, maIsEcho, maIsLocal, maReserved, naKillAfter, naSent,
      naFile, naCrash, naReqRead, naAudit, naIsReceipt, naReserved,
      inKillAfter, inPublic, inSent, inReqRead, inIsReceipt, inBase64,
      inSQZ, inReserved, faReserved0, faReserved1, faReserved2, faReserved3,
      faReserved4, faReserved5, faReserved6, faReserved7);
/////////////////////////////////////////////////////////////////////////////
// Message Block Zero - is the first 8 bytes of ALL MSG files!
/////////////////////////////////////////////////////////////////////////////
   MessageBlockZero = Packed Record
      LoMsgNumber : LongWord;
      HiMsgNumber : LongWord;
   End;
   MessageIDX = Packed Record
      MsgNumber : LongWord;
      SeekToPos : LongWord;
   End;
   MessageHdr = Packed Record
      BlockSize    : Word;     // 2 bytes are stored but is size to read the
                               // rest of this header to EndSignature+5 mainly
                               // to make sure you read this comment!
{00}  MsgNumber    : LongWord;
{08}  Flags        : Set of MessageHdrBits;
{10}  CreatedOn    : TTimestamp;
{18}  CreatedBy    : LongWord; // RecordID from Userbase
{20}  ReceivedOn   : TTimestamp;
{28}  SentOn       : TTimestamp;
{30}  TimesRead    : LongWord;
{38}  BodyStart    : LongWord;
{40}  BodySize     : LongWord;
{48+} MsgFrom      : ShortString;
{n+}  MsgTo        : ShortString;
{n+}  MsgSubject   : ShortString;
{n+}  EndSignature : Array[0..4] of Char;
   End;

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
   FTS0001Stored = Packed Record
      fromUserName:Array[1..36] of Char;
      toUserName:Array[1..36] of Char;
      subject:Array[1..72] of Char;
      createDateTime:Array[1..20] of Char; // "01 Jan 86  02:34:56" or "Mon  1 Jan 86 02:34"
      timesRead:Word;
      destNode:Word;
      origNode:Word;
      cost:Word;
      origNet:Word;
      destNet:Word;
      destZone:Word;
      origZone:Word;
      destPoint:Word;
      origPoint:Word;
      replyTo:Word;
      Attribute:Word;
      nextReply:Word;
      // text (null terminated, #0A#0D#0A#0D, #1A)
   End;
   //////////////////////////////////////////////////////////////////////////
   // AttributeWord   bit       meaning
   //                 ---       --------------------
   //                   0       Private
   //                   1       Crash
   //                   2       Recd
   //                   3       Sent
   //                   4       FileAttached
   //                   5       InTransit
   //                   6       Orphan
   //                   7       KillSent
   //                   8       Local
   //                   9       HoldForPickup
   //                  10       unused
   //                  11       FileRequest
   //                  12       ReturnReceiptRequest
   //                  13       IsReturnReceipt
   //                  14       AuditRequest
   //                  15       FileUpdateReq
   // text notes:
   // $0D = Hard CR
   // $8D = Soft CR
   // $0A = LF (Ignored)
   // $01 = CTRL-A Kludge Line #00
   //     = ^A TOPT <Point #>#0 - Destination Point Address
   //     = ^A FMPT <Point #>#0 - Origin Point Address
   //     = ^A INTL <dest zone:net/node> <orig zone:net/node>#0
   //       - Used for International Addressing
   //////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
   FTS0001Packed = Packed Record
{00}  PakdMessage:Word; // $20 $00
{02}  origNode:Word;
{04}  destNode:Word;
{06}  origNet:Word;
{08}  destNet:Word;
{0A}  Attribute:Word;
{0C}  cost:Word;
{0E}  createDateTime:Array[1..20] of Char; // "01 Jan 86  02:34:56" or "Mon  1 Jan 86 02:34"
      fromUserName:PChar;
      toUserName:PChar;
      subject:PChar;
      // text (null terminated)
   End;

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
   FTS0001PacketHdr = Packed Record
{00}  origNode:Word;
{02}  destNode:Word;
{04}  Year:Word;
{06}  Month:Word;
{08}  Day:Word;
{0A}  Hour:Word;
{0C}  Minute:Word;
{0E}  Second:Word;
{10}  Baud:Word;
{12}  Vers:Word; // 02 00
{14}  origNet:Word;
{16}  destNet:Word;
{18}  prodCode:Byte;
{19}  serialNo:Byte;
{1A}  password:Array[1..8] of Char;
      origZone:Word;
      destZone:Word;
      fill:Array[1..20] of Char;
      // messages //
   end;
   //////////////////////////////////////////////////////////////////////////
   // AREA:AREA_NAME#0
   // --- <small product signature>#0D
   // * Origin: <name of BBS> (1:123/123)#0D
   // SEEN-BY: NET/NODE NET/NODE NODE NODE#0D
   // ^A PATH: NET/NODE NET/NODE#00
   //////////////////////////////////////////////////////////////////////////
var
   LastArea:LongWord;
   AreaStr:String[5];
   ZeroRec:MessageBlockZero;
   IFH,BFH,MFH:File;

procedure IsAreaDifferent(Area:LongWord;Var IFH,MFH,BFH:File);
Var
   NW:Longint;

Begin
   If Area<>LastArea then begin
      If LastArea<>0 then Begin
         CloseFile(IFH);
         CloseFile(MFH);
         CloseFile(BFH);
      End;
      LastArea:=Area;
      AreaStr:=IntToHex(Area,5);
      Writeln('Processing Area '+AreaStr);
      AssignFile(IFH, 'MSG'+AreaStr+'.IDX');
      AssignFile(BFH, 'MSG'+AreaStr+'.HDR');
      AssignFile(MFH, 'MSG'+AreaStr+'.BDY');
      If FileExists('MSG'+AreaStr+'.IDX') then begin
         Reset(IFH, 1);
         BlockRead(IFH, ZeroRec, SizeOf(MessageBlockZero), Nw);
         SeekFile(IFH, 0);
         Inc(ZeroRec.HiMsgNumber);
      end
      else begin
         Rewrite(IFH, 1);
         ZeroRec.LoMsgNumber:=1;
         ZeroRec.HiMsgNumber:=1;
      end;
      BlockWrite(IFH, ZeroRec, SizeOf(MessageBlockZero), Nw);

      If FileExists('MSG'+AreaStr+'.HDR') then Reset(BFH, 1)
      Else Rewrite(BFH, 1);
      BlockWrite(BFH, ZeroRec, SizeOf(MessageBlockZero), Nw);

      If FileExists('MSG'+AreaStr+'.BDY') then Reset(MFH, 1)
      Else Rewrite(MFH, 1);
      SeekFile(MFH, FileSize(MFH));
   end
   else Begin
      Inc(ZeroRec.HiMsgNumber);

      SeekFile(IFH, 0);
      BlockWrite(IFH, ZeroRec, SizeOf(MessageBlockZero), Nw);

      SeekFile(BFH, 0);
      BlockWrite(BFH, ZeroRec, SizeOf(MessageBlockZero), Nw);
   End;
// At end of IDX header, wait for DAT size
   SeekFile(IFH, FileSize(IFH));
   SeekFile(BFH, FileSize(BFH));
End;

procedure AppendMessage(Area:LongWord;Msg:MessageHdr;MsgBody:String;var IFH,BFH,MFH:File);
//AREAS: 0=Feedback to System, $00001 to $FFFFF areas (1,048,576)
var
   Idx:MessageIdx;
   Nw,X:Longint;
   Ws:String;
   Len:Byte;

Begin
   IsAreaDifferent(Area,IFH,MFH,BFH);

// store IDX:
   Idx.MsgNumber:=ZeroRec.HiMsgNumber;
   Idx.SeekToPos:=FileSize(BFH);
   BlockWrite(IFH, Idx, SizeOf(Idx), Nw);

// Store Body and Update Header Size(s):
   Msg.BodyStart:=FileSize(MFH);

   If inSQZ in Msg.Flags then begin
      LH6Compress(MsgBody, Ws);
      Msg.BodySize:=Length(Ws);
      BlockWrite(MFH, Ws[1], Msg.BodySize, Nw);
   end
   else begin
      Msg.BodySize:=Length(MsgBody);
      BlockWrite(MFH, MsgBody[1], Msg.BodySize, Nw);
   End;

// Store Message Header:
   Msg.BlockSize:=SizeOf(Msg.MsgNumber)+
      SizeOf(Msg.Flags)+
      SizeOf(Msg.CreatedOn)+
      SizeOf(Msg.CreatedBy)+
      SizeOf(Msg.ReceivedOn)+
      SizeOf(Msg.SentOn)+
      SizeOf(Msg.TimesRead)+
      SizeOf(Msg.BodyStart)+
      SizeOf(Msg.BodySize)+
      Length(Msg.MsgFrom)+1+
      Length(Msg.MsgTo)+1+
      Length(Msg.MsgSubject)+1+
      SizeOf(Msg.EndSignature);
   Msg.MsgNumber:=ZeroRec.HiMsgNumber;
   Msg.EndSignature[0]:=#255;
   Msg.EndSignature[1]:=#254;
   Msg.EndSignature[2]:=#253;
   Msg.EndSignature[3]:=#252;
   Msg.EndSignature[4]:=#251;

   If Area=2 then begin
     BlockWrite(BFH, Msg.BlockSize, SizeOf(Msg.BlockSize), Nw);
     BlockWrite(BFH, Msg.MsgNumber, SizeOf(Msg.MsgNumber), Nw);
     BlockWrite(BFH, Msg.Flags, SizeOf(Msg.Flags), Nw);
     BlockWrite(BFH, Msg.CreatedOn, SizeOf(Msg.CreatedOn), Nw);
     BlockWrite(BFH, Msg.CreatedBy, SizeOf(Msg.CreatedBy), Nw);
     BlockWrite(BFH, Msg.ReceivedOn, SizeOf(Msg.ReceivedOn), Nw);
     BlockWrite(BFH, Msg.SentOn, SizeOf(Msg.SentOn), Nw);
     BlockWrite(BFH, Msg.TimesRead, SizeOf(Msg.TimesRead), Nw);
     BlockWrite(BFH, Msg.BodyStart, SizeOf(Msg.BodyStart), Nw);
     BlockWrite(BFH, Msg.BodySize, SizeOf(Msg.BodySize), Nw);
     Len:=Length(Msg.MsgFrom); BlockWrite(BFH, Len, 1, Nw);
     BlockWrite(BFH, Msg.MsgFrom[1], Length(Msg.MsgFrom), Nw);
     Len:=Length(Msg.MsgTo); BlockWrite(BFH, Len, 1, Nw);
     BlockWrite(BFH, Msg.MsgTo[1], Length(Msg.MsgTo), Nw);
     Len:=Length(Msg.MsgSubject); BlockWrite(BFH, Len, 1, Nw);
     BlockWrite(BFH, Msg.MsgSubject[1], Length(Msg.MsgSubject), Nw);
     BlockWrite(BFH, Msg.EndSignature, SizeOf(Msg.EndSignature), Nw);
   end
   else begin
     SetLength(Ws,Msg.BlockSize+2);
     X:=Msg.BlockSize-(Length(Msg.MsgFrom)+1+
        Length(Msg.MsgTo)+1+Length(Msg.MsgSubject)+1+2);
     Move(Msg,Ws[1],X);
     Len:=Length(Msg.MsgFrom);
     Move(Len,Ws[X],1);
     Move(Msg.MsgFrom[1],Ws[X+1],Len);
     Inc(X,Len+1);
     Len:=Length(Msg.MsgTo);
     Move(Len,Ws[X],1);
     Move(Msg.MsgTo[1],Ws[X+1],Len);
     Inc(X,Len+1);
     Len:=Length(Msg.MsgSubject);
     Move(Len,Ws[X],1);
     Move(Msg.MsgSubject[1],Ws[X+1],Len);
     Inc(X,Len+1);
     Move(Msg.EndSignature[0],Ws[x],5);
     BlockWrite(BFH,Ws[1],Msg.BlockSize+2,Nw);
   End;
End;

procedure WriteMessage(var IFH,BFH,MFH:File);
var
   Msg:MessageHdr;
   MsgBody,UUID:String;

Begin
   FillChar(Msg, SizeOf(Msg), #0);
   //Msg.Flags:=[inSQZ];
   Msg.Flags:=[];
   Msg.CreatedOn:=Timestamp;
   Msg.CreatedBy:=0;
   Msg.ReceivedOn:=-1;
   Msg.SentOn:=-1;
   Msg.TimesRead:=0;
   Msg.MsgFrom:='Ozz Nixon';
   Msg.MsgTo:='ALL';
   Msg.MsgSubject:='Brand new message format, originally called PeanutButter (to go with JAM)';

   MsgBody:=#1'Kludge: CTRL-A lines are stored at the start of the message.'+
      #1'INTL 1:362/288 2:2/0'+
      #1'TOPT 0'+
      #1'FOPT 1'+
      #1'FLAGS: PGM'+    // program generated
      #1'PID: XBBS/MP2'+ // program signature
      #1'IGW: modernpascal.com'+#13#10+ // end of kludge(s)
      #13#10+ // msg body starts with CRLF (even if not KLUDGES!)
      'Hello All!'+#13#10+
      #13#10+
      'We have successfully built our own Pascal engine, and have spent the past few months '+
      'focusing on its ability to handle standalone, apache web, and listener driven '+
      'environments so someone could build their own BBS. I am now focusing on a proprietary '+
      'message format I had made the same year J.A.M. came out. I had focused on making a '+
      'format capable of handling messages found on any network. To achieve this, I had to '+
      'build a dynamic header, so I am not limited to currently known structure sizes. This '+
      'engine supports fields up to 255 bytes in size, and basically unlimited kludge lines '+
      'and unlimited message body size. With boundary encoding you can mix attachments and '+
      'message bodies in the same message. This means you can also use the boundary to have '+
      'plain/text, ansi/text, and html/text message bodies in the same message - separated '+
      'by boundary lines and enclosed with the content-type. Now, 3 decades later, I have '+
      'revised the code, fixing any bugs, testing the base concept and applying what I have '+
      'learned about Internet message formats to find PB still works perfectly.'#13#10+
      #13#10+
      'Ozz Nixon'+#13#10+
      '1:362/288.0'+#13#10+
      'The_NET,Chattanooga_TN,Ozz_Nixon,1-423-842-6743,9600,CM,HST,V32b,V42b,V34,VFC'+#13#10+
      'Sweet_Perfume_Of_Blood_(Commercial),Chattanooga_TN,Ozz_Nixon,1-615-874-0390,9600,CM,V32b,V42b,UVFC'+#13#10+
      'Sweet_Perfume_Of_Sex_(Adult),Chattanooga_TN,Karen_Campasino,1-615-874-0391,9600,CM,V32b,V42b,HST'+#13#10+
      '--- Tearline v1.0'+#13#10+
      ' * Origin: Exchange BBS (0:0/0.0) Bringing BBSing back to the desktop computer'+#13#10+
      'SEEN-BY: 362/288'+#13#10#0#0#0;
   UUID:=Copy(MakeUUID,1,18)+'.'+CRC32(MsgBody,0);
   Writeln(UUID);
      MsgBody:=#1'MSGID: '+UUID+MsgBody;
   AppendMessage(1,Msg,MsgBody,IFH,BFH,MFH);
end;

Begin
Glock();
   LastArea:=0;

   For var Loop2:=1 to 1000000 do
      WriteMessage(IFH,BFH,MFH);

   CloseFile(BFH);
   CloseFile(MFH);
   CloseFile(IFH);
GUnlock();
end.
