procedure SCAN_USERS;
            var U:USER;
            begin
               assign(USRS,USER_FILE);reset(USRS);
               read(USRS,U);
               while not eof(USRS) do
                  begin
                      with U do
                           writeln(FN:15,LN:15,AD:25,LG:5);
                      read(USRS,U)
                  end;
               writeln;writeln('**** end of survey ****');writeln;
               write(CONTINUE);while not keypressed do;writeln;
            end;{SCAN_USERS}
