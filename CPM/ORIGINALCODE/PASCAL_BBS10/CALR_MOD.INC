    procedure LIST_CALLERS;
        var U:CALLER;
            I:integer;
        begin
            assign(CALR, CALLER_FILE);reset(CALR);
            I:=filesize(CALR);
            while not EOF(CALR) do
                 begin
                   read(CALR,U);
                   writeln(I:4,' ' + U.FN + ' ' + U.LN + ' ' + U.AD );
                   I:=I-1;
                 end;
             close(CALR);
             writeln;
         end;
