procedure GET_SYSOP_MESSAGES;
           var S:SUMMARY;
               M:MESSAGE;
               I:integer;
               AN:LINE;
           begin
               assign(SUMRY,SUMMARY_FILE);reset(SUMRY);
               repeat
                   read(SUMRY,S);
                   if (S.T='SYSOP') and (S.PW='*') then
                      begin
                        assign(MSG,MESSAGE_FILE);reset(MSG);
                        repeat
                           readln(MSG,M.SZ,M.N);
                           for I:=1 to M.SZ do
                                 readln(MSG,M.TXT[I]);
                        until (S.FILE_POS = M.N) or eof(MSG);
                        if S.FILE_POS=M.N then
                           begin
                             LIST_MESSAGE(S,M);
                             writeln;write(CONTINUE);
                             AN:=READ_STRING;writeln
                           end;
                     end;
                until eof(SUMRY);
                close(MSG);close(SUMRY);
           end; {GET_SYSOP_MESSAGES}
