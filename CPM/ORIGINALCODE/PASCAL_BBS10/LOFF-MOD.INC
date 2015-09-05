procedure LOGOFF(NM:LINE);
        label 8;
        var EXIT_PROG:file;
            STATUS_OK:boolean;
        procedure TEST_ENTRY(var OK_TO_ENTER_CPM : boolean);
          var PW:PWORD;
          begin
             writeln;write('Enter CPM PASSWORD: ');PW:=READ_STRING;writeln;
             if PW = TRD_PASS then
                 OK_TO_ENTER_CPM:=true
              else
                 OK_TO_ENTER_CPM:=false;
           end;
        begin
          writeln;
          if (HANG_UP or BACK_TO_CPM) and (FN<>'SYSOP') then
             begin
                 writeln;write('Enter confidential comments for the SYSOP? (Y/N)');
                 ANS:=READ_STRING;writeln;
                 if ANS[1]='Y' then
                     begin SYSOP_MESSAGE:=true;ENTER_MESSAGE;SYSOP_MESSAGE:=false end;
             end;
          if BACK_TO_CPM then
             begin
               if QUICK_LOGON then RETNOK_FLAG:=0;
               DU:=0;
               if CPM_PASS then
                  TEST_ENTRY(STATUS_OK)
               else
                  STATUS_OK:=true;
               if STATUS_OK then
                  begin
                      writeln;writeln('Entering CPM...');
                      BASE:=JUMP
                  end
               else
                   goto 8
             end
          else
             begin
               if HANG_UP then
                   begin
                     writeln('thanks for calling ',NM,' ...');writeln;
                     writeln('Please call again');
                     RETNOK_FLAG:=0;
                   end
               else
  8            :   begin
                     writeln('Sorry, too many errors or access denied to invalid user ! ');
                     writeln ;writeln('Try again another time, Bye..');
                   end;
                BASE:=JUMP;
                bdos(SELUSER,0);
                assign(EXIT_PROG,'BYE.COM');
                execute(EXIT_PROG);
            end;
        end;
