STRING;
                    val(ISTR,I,ER);
                end;
              if (ER<>0) or (I> UDATA.MNO) then goto 13;
              assign(SUMRY,SUMMARY_FILE);
              if (EXIST(SUMMARY_FILE)) then
                 begin
                     reset(SUMRY);
                     seek(SUMRY,I-1);
                     read(SUMRY,SUM);
                     close(SUMRY);
                     if not SUM.ACT then goto 13;
                     assign(MSG,MESSAGE_FILE);
                     reset(MSG);
                     repeat
                         readln(MSG,M.SZ,M.N);
                         for I:=1 to M.SZ do
                                readln(MSG,M.TXT[I]);
                     until SUM.FILE_POS = M.N;
                     close(MSG);
                     PASS_CK:=true;
                     LIST_MESSAGE(SUM,M);
                     writeln;write(CONTINUE);
                     AN:=READ_STRING;writeln;
                     PASS_CK:=false
                 end
              else
13:              begin
                   writeln;
                   writeln('There is no ACTIVE record of that value in  storage');
                   delay(DELAY_TIME);
                 end;
         end;  {RETRIEVE_MESSAGE}
