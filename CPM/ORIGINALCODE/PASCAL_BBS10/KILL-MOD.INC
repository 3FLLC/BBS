procedure KILL_MSG(S:LINE);
          label 15;
          var I,ER:integer;
              ISTR:LINE;
              SUM:SUMMARY;
              ST:STATISTICS;
              LAST_CALLER,FN,LN,FNT,FNF,LNT,LNF:LINE;
              N:integer;
          begin
              ISTR:=copy(S,pos(';',S)+1,length(S)-pos(';',S));
              val(ISTR,I,ER);
              if ER <> 0 then
                 begin
                    write('Message number to KILL?: ');
                    ISTR:=READ_STRING;
                    val(ISTR,I,ER);
                    if ER<>0 then goto 15
                 end;
              assign(STAT,STATISTIC_FILE);
              reset(STAT);
              read(STAT,ST);
              close(STAT);
              if (I>0) and (I<=UDATA.MNO) and (ST.AC>0) then
                 begin
                     assign(LCALR,LAST_CALLER_FILE);
                     reset(LCALR);
                     read(LCALR,LAST_CALLER);
                     close(LCALR);
                     LAST_CALLER:=copy(LAST_CALLER,pos(' ',LAST_CALLER)+1,
                                       length(LAST_CALLER)-pos(' ',LAST_CALLER));
                     GET_NAMES(LAST_CALLER,FN,LN);
                     assign(SUMRY,SUMMARY_FILE);
                     reset(SUMRY);
                     seek(SUMRY,I-1);
                     read(SUMRY,SUM);
                     GET_NAMES(SUM.T,FNT,LNT);
                     GET_NAMES(SUM.F,FNF,LNF);
                     if (FN='SYSOP') or ((FN[1]+'. '+LN)=(FNT[1]+'. '+LNT))
                        or((FN[1]+'. '+LN)=(FNF[1]+'. '+LNF)) then
                        begin
                            if VERBOSE then
                                  begin
                                  writeln;write('Killing Message #',I,' and Updating SUMMARY,');
                                  end;
                            SUM.ACT:=false;
                            seek(SUMRY,filepos(SUMRY)-1);
                            write(SUMRY,SUM);
                            close(SUMRY);
                            if VERBOSE then write('and STATS file');
                            assign(STAT,STATISTIC_FILE);
                            reset(STAT);
                            read(STAT,ST);
                            ST.AC:=ST.AC-1;
                            seek(STAT,filepos(STAT)-1);
                            write(STAT,ST);
                            close(STAT);
                        end
                     else
                        goto 15
                 end
             else
                 begin
 15:                 writeln;writeln('Not possible to Kill indicated Message');
                     gotoXY(1,PAGE_BOTTOM);
                 end;
                 delay(delay_time);
         end; {KILL_MSG}
