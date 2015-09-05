procedure ADD_USERS;
           label 16;
           var U:USER;
               ANS:LINE;
               CH:char;
           begin
             writeln;
             UP_CASE:=true;
             repeat
                 clrscr;
 16        :     with U do
                   begin
                      write('Users FIRST name: ');FN:=READ_STRING;writeln;
                      write('...and LAST name: ');LN:=READ_STRING;writeln;
                      write('...Default pass : ');PW:=READ_STRING;writeln;
                      LG:=0;
                      write('....and  ADDRESS: ');AD:=READ_STRING;writeln;
                   end;
                 write('Any corrections? (Y/N) ');ANS:=READ_STRING;writeln;
                 if ANS[1] = 'Y' then goto 16;
                 assign(USRS,USER_FILE);
                 if EXIST(USER_FILE) then
                    begin reset(USRS);seek(USRS,filesize(USRS));U.FPOS:=filesize(USRS)+1 end
                 else
                    begin rewrite(USRS);U.FPOS:=1 end;
                 write(USRS,U);
                 close(USRS);
                 writeln;writeln;
                 write('Type CTL C to end, any other key to continue ');
                 read(KBD,CH);writeln;
              until CH = chr(3);
              writeln;
          end; {ADD_USERS}
          
