procedure SCAN_SUMMARY;
             var S:SUMMARY;
                 START,TSTART,ER:integer;
                 ANS:LINE;
                 NOSUM:boolean;
                 CH:char;
             begin
                 assign(SUMRY,SUMMARY_FILE);
                 if EXIST(SUMMARY_FILE) then
                    begin
                        reset(SUMRY);
                        START:=0;TSTART:=0;
                        NOSUM:=false;
                        ER:=1;
                        repeat
                            read(SUMRY,S);
                            if S.ACT then TSTART:=S.FILE_POS
                        until (S.ACT) or eof(SUMRY) ;
                        write('Message number: (',TSTART,'-',UDATA.MNO,
                              ') to start (RETURN to quit)');
                        repeat
                             ANS:=READ_STRING;
                             if length(ANS)=0 then
                                 begin
                                    delLine;
                                    write('Message number: (',TSTART,'-',UDATA.MNO,
                                          ') to start (RETURN to quit)');
                                 end
                              else
                                 VAL(ANS,START,ER);
                              if length(ANS)=0 then
                                    NOSUM:= true;
                        until (ER=0) or (NOSUM);
                        if not (NOSUM) and (START>0) and (START <= UDATA.MNO) then
                             begin
                                  seek(SUMRY,START-1);
                                  clrscr;
                                  writeln('Message');
                                  writeln('  Num':5,'Date':9,'From':15,'To':17,'Subject':20);
                                  repeat
                                      read(SUMRY,S);
                                      if S.ACT then
                                             begin
                                                writeln;
                                                write(S.FILE_POS:4,S.DT:12,S.F:14,S.T:17);
                                                if S.PW<>DEF_PASS then
                                                     writeln(' *':SUB_LEN+1)
                                                 else
                                                     writeln(S.SUB:SUB_LEN+1);
                                             end;
                                  until EOF(SUMRY);
                                  close(SUMRY);
                              end;{ER=0}
                     end;
                     writeln;writeln('**** end of survey ****');writeln;
                     writeln;write(CONTINUE);
                     read(TRM,CH)
             end; {SCAN_SUMMARY}
