
procedure ENTER_MESSAGE;
  label 10,11;
  var  MG:MESSAGE;
       SUM:SUMMARY;
       ANS,FN,LN:LINE;
       NO,I:integer;
       IS_USER:boolean;
   procedure SAVE_MSG(M:MESSAGE;SUM:SUMMARY);
     var S:STATISTICS;
        I:integer;
        TEMP:text;
        CH:char;
     procedure APPEND(M:MESSAGE);
       var F:text;
           I:integer;
           CH:char;
       begin
           assign(MSG,MESSAGE_FILE);
           assign(F,'TEMP.FIL');
           rewrite(F);
           if EXIST(MESSAGE_FILE) then
              begin
                reset(MSG);
                while not eof(MSG) do
                    begin read(MSG,CH);write(F,CH) end;
                close(MSG);
                erase(MSG)
              end
           else
               rewrite(MSG);
           writeln(F,M.SZ,' ',M.N);
           for I:=1 to M.SZ do
              writeln(F,M.TXT[I]);
           close(F);
           rename(F,MESSAGE_FILE);
       end;

    begin

     if VERBOSE then begin writeln;write('Updating SUMMARY,') end;
     if SUM.T <> 'SYSOP' then SUM.ACT:=true else SUM.ACT:=false;
     assign(SUMRY,SUMMARY_FILE);
     if EXIST(SUMMARY_FILE) then
         reset(SUMRY)
     else
         rewrite(SUMRY);
     seek(SUMRY,filesize(SUMRY));
     SUM.FILE_POS:=filesize(SUMRY)+1;M.N:=SUM.FILE_POS;
     write(SUMRY,SUM);
     close(SUMRY);
     if VERBOSE then write('MESSAGE,');
     APPEND(M);
     if VERBOSE then writeln('and STATS files...');
     assign(STAT,STATISTIC_FILE);reset(STAT);
     read(STAT,S);
     close(STAT);
     S.MNO:=M.N;if not SYSOP_MESSAGE then  S.AC:=S.AC+1;
     rewrite(STAT);
     write (STAT,S);
     close(STAT);
     if VERBOSE then begin writeln;writeln('Message number ',M.N, ' saved') end;
   end;  {SAVE_MSG}
  procedure EDIT_HEADER(var S:SUMMARY);
           var T:SUMMARY;
           begin
              clrscr;
              writeln('Enter replacement or RETURN for no change');
              write('Date: ',S.DT,' :');T.DT:=READ_STRING;if length(T.DT)>0 then S.DT:=T.DT;writeln;
              write('From: ',S.F,' :');T.F:=READ_STRING;if length(T.F)>0 then S.F:=T.F;writeln;
              write('Subject: ',S.SUB,' :');T.SUB:=READ_STRING;if length(T.SUB)>0 then S.SUB:=T.SUB;writeln;
              write('PW     : ',S.PW,' :');T.PW:=READ_STRING; if length(T.PW)>0 then S.PW:=T.PW;writeln;
              writeln;
           end;
  procedure EDIT_MESSAGE( var M:MESSAGE);
        var I,ER:integer;
            ISTR:LINE;
        begin
            I:=0;
            repeat
               writeln;
               writeln('Enter Line Number to change (RETURN or 0 to end) ');
               write('Then enter Replacement or Return fo NO change: ');
               ISTR:=READ_STRING;writeln;
               val(ISTR,I,ER);
               if length(ISTR)>0 then
                  begin
                    UP_CASE:=false;
                    writeln('Line number ',I,' was: ');
                    writeln( '  :',M.TXT[I]);
                    write(I,':');M.TXT[I]:=READ_STRING;writeln;
                    UP_CASE:=true;
                  end;
                until length(ISTR)=0;
        end;  {EDIT_MESSAGE}
  procedure GET_MSG_PASS(var S:PWORD);
        begin
             write('Enter up to ',PASS_LEN,' characters for your PASSWORD: ');
             S:=READ_STRING;
             writeln;
        end;                   {GET_PASS}
  procedure CHECK_FILES(FN,LN:LINE;var OK:boolean);
    var U:USER;
    begin
       assign(USRS,USER_FILE);reset(USRS);
       repeat
           read(USRS,U);
       until (EOF(USRS)) or ((FN=U.FN) and (LN=U.LN));
       close(USRS);
       if (FN=U.FN) and (LN=U.LN) then
          OK:=true
       else
          OK:=false;
    end; {FILE_CHECK}
    begin
       clrscr;
       if SYSOP_MESSAGE then
          begin SUM.T:='SYSOP';SUM.PW:='*' end
       else
          begin
             write('To (RETURN for All): ');
             SUM.T:=READ_STRING;
             if length(SUM.T)=0 then
                begin write('All');SUM.T:='All';SUM.PW:=DEF_PASS end;
             writeln
          end;
       if (not SYSOP_MESSAGE) and (SUM.T<>'All') then
          begin
             GET_NAMES(SUM.T,FN,LN);
             CHECK_FILES(FN,LN,IS_USER);
             case IS_USER of
                true: begin
                          write('Password (* for Personal any other key to skip');
                          ANS:=READ_STRING;writeln;
                          if ANS = '*' then
                             GET_MSG_PASS(SUM.PW)
                          else
                             SUM.PW:=DEF_PASS
                       end;
                false: begin
                         write(SUM.T, ' is not a current user, OK? (Y/N) ');
                         ANS:=READ_STRING;writeln;
                         if ANS[1] = 'Y' then
                            SUM.PW:=DEF_PASS
                         else
                            SUM.PW:= 'INVAL'
                       end;
             end; {OF CASE}
         end;
       if SUM.PW <> 'INVAL' then
             begin
                UDATA.MNO:=UDATA.MNO+1;
                assign(LCALR,LAST_CALLER_FILE);reset(LCALR);
                readln(LCALR,NO,SUM.F);
                close(LCALR);
                writeln('From:    ',SUM.F);
                write('Date:    ');SUM.DT:=READ_STRING;writeln;
                write('Subject: ');SUM.SUB:=READ_STRING;writeln;writeln;
                writeln('Enter up to ',MSG_LEN, ' lines of text');
                writeln('When finished enter two RETURNSs in a row');writeln;
                I:=1;UP_CASE:=false;
                repeat
11   :              write(I:3,'> ');
                    MG.TXT[I]:=READ_STRING;
                    I:=I+1; writeln;
                    if (I>MSG_LEN-3) and (MSG_LEN-I+1>0) then
                         begin
                             if BELL then write(chr(7));
                             if MSG_LEN-I+1=1 then
                                 writeln( 'Last line ...')
                              else
                                 writeln( MSG_LEN-I+1, ' lines left...');
                          end;
               until (Length(MG.TXT[I-1])=0)  or (I>MSG_LEN);
               if I>MSG_LEN then
                    begin writeln;writeln(chr(7),'Message FULL');end;
               MG.SZ:=I-2;
               UP_CASE:=true;
               repeat
10   :             writeln;write(MG_PROMPT);ANS:=READ_STRING;writeln;
                   case ANS[1] of
                    'H':EDIT_HEADER(SUM);
                    'E':EDIT_MESSAGE(MG);
                    'L':LIST_MESSAGE(SUM,MG);
                    'S':begin
                            SAVE_MSG(MG,SUM);
                            ANS[1]:='A'
                        end;
                    'C':begin UP_CASE:=false;
                              clrscr;
                              LIST_MESSAGE(SUM,MG);
                              I:=MG.SZ+1;
                              goto 11
                         end;
                    'A':begin
                          writeln;writeln('Abandoning Message Number ',UDATA.MNO);
                          UDATA.MNO:=UDATA.MNO-1;
                          delay(DELAY_TIME);
                        end
                    else
                      begin writeln('Invalid choice !');ANS[1]:='A' end;
                   end;{of CASE}
                until ANS[1]='A';
         end; {if NOT inval}
    end; {ENTER_MESSAGE}
