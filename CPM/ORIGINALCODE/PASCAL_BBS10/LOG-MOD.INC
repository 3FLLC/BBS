    procedure LOGON(var FN:LINE);
      var N:USER;
          PW,ANS,LN:LINE;
          I:integer;
          SEARCHING:boolean;
      procedure CHECK_FOR_MESSAGES;
        type PTR = ^NODE;
             NODE = record
                    MSG_NUM:integer;
                    LINK:PTR
                    end;
        var TOP,P,Q:PTR;
            SUM:SUMMARY;
            TFN,TLN:LINE;
        begin
            TOP:=nil;
            assign(SUMRY,SUMMARY_FILE);
            if EXIST(SUMMARY_FILE) then
               begin
                   reset(SUMRY);
                   repeat
                         read(SUMRY,SUM);
                         GET_NAMES(SUM.T,TFN,TLN);
                         if (FN[1]=TFN[1]) and (LN=TLN) and (SUM.ACT) then
                            begin
                                if TOP = nil then
                                   begin
                                      NEW(P);
                                      P^.MSG_NUM:=SUM.FILE_POS;
                                      P^.LINK:=nil;
                                      TOP:=P
                                   end
                                else
                                   begin
                                      NEW(Q);
                                      Q^.MSG_NUM:=SUM.FILE_POS;
                                      Q^.LINK:=nil;
                                      P^.LINK:=Q;
                                      P:=Q
                                   end;
                            end; {IF FN....}
                   until eof(SUMRY);
                   close(SUMRY);
                   if TOP <> nil then
                      begin
                         writeln;writeln(FN,' you have mail.....');
                         writeln('Please Retreive and Kill the following MESSAGE(S): ');
                         write('(');
                         repeat
                            write(TOP^.MSG_NUM:4);
                            TOP:=TOP^.LINK
                         until TOP = nil;
                         writeln(')':2);
                         delay(DELAY_TIME)
                      end
               end {IF EXIST...}
         end;   {CHECK_FOR_MESSAGES}
      procedure UPDATE_FILES(N1:USER);
        var N2:CALLER;
        begin
           if VERBOSE then write(',CALLER,');
           assign(CALR, CALLER_FILE);
           if EXIST(CALLER_FILE) then
                reset(CALR)
           else
                rewrite(CALR);
           seek(CALR,filesize(CALR));
           N2.FN:=N1.FN;N2.LN:=N1.LN;N2.AD:=N1.AD;
           WRITE(CALR,N2);
           close(CALR);
           if VERBOSE then write('LASTCALR');
           assign(LCALR, LAST_CALLER_FILE);rewrite(LCALR);
              write(LCALR,N.FPOS , ' ' + N.FN+' '+N.LN);
           close(LCALR);
           if VERBOSE then writeln(' and STATS files...');
           assign(STAT,STATISTIC_FILE);
           UDATA.US:=UDATA.US+1;
           rewrite(STAT);
              write(STAT,UDATA);
           close(STAT);
           writeln;writeln;
           if VERBOSE then
              begin
                 writeln('You are Caller Number:            ',UDATA.US);writeln;
                 writeln('Number of ACTIVE System Messages: ',UDATA.AC);writeln;
                 writeln('LAST System Message Number:       ',UDATA.MNO);writeln;
                 writeln;
                 DELAY(DELAY_TIME);
              end;
        end;{UPDATE_FILES}
     procedure GET_NEW_USER(FN,LN:LINE;var N:USER);
       label 7;
       var ANS,ADDR,PWRD:LINE;
                       L:INTEGER;
       begin
             N.FN:=FN;N.LN:=LN;
      7      : begin
                    write('Enter YOUR City,State: ');
                    N.AD:=READ_STRING;writeln;writeln;
                    writeln('Hello ' + N.FN + ' ' + N.LN + ' From ' + N.AD);
                    writeln;write('Is anything Misspelled? ');
                    ANS:=READ_STRING;writeln;
                    if (ANS[1] = 'Y')  then
                       begin
                           writeln('OK, lets try again');
                           goto 7
                        end;
                    PASS_CK:=true;
                    GET_PASS(N.PW);
                    PASS_CK:=false;
                    N.LG:=0;N.FPOS:=filesize(USRS);
                 end;
        end;{GET_NEW_USER}
      begin
        SEARCHING:=true;
        TRY:=0; {check init}
        while (TRY < MAX_TRY) and (SEARCHING) do
           begin
               TRY:=TRY+1;
               if BELL then writeln(Chr(7));
               write('Enter your FIRST name: ');FN:=READ_STRING;writeln;
               if FN<>FST_PASS then
                  begin
                     if BELL then writeln(chr(7));
                     if FN = 'SYSOP' then PASS_CK:=true;
                     write('    and your LAST name: ');LN:=READ_STRING;writeln;
                     PASS_CK:=false;writeln;writeln;
                     if (FN + LN <> 'SYSOP'+ SND_PAS) and (length(FN)>0) and (length(LN)>0) then
                         begin
                           writeln('Checking USER file....');writeln;
                           if EXIST(USER_FILE) then
                              begin
                                assign(USRS,USER_FILE);
                                reset(USRS);
                                read(USRS,N);
                                I:=0;
                                while not eof(USRS) and (N.FN<>FN) and (N.LN<>LN) do
                                   begin
                                     read(USRS,N);
                                     I:=I+1
                                   end;
                                if (N.FN=FN) and (N.LN = LN) then
                                   begin
                                       PASS_CK:=true;
                                       write('Enter your PASSWORD: ');PW:=READ_STRING;writeln;
                                       PASS_CK:=false;
                                       if PW=N.PW then
                                          begin
                                             SEARCHING:=false;
                                             writeln;writeln;
                                             writeln('Logging name to disk....');
                                             writeln;
                                             N.LG:=N.LG+1;
                                             if VERBOSE then begin writeln;write('Closing USERS and Updating')end;
                                             seek(USRS,I);write(USRS,N);close(USRS);
                                             UPDATE_FILES(N);
                                             BBON:=true;
                                          end
                                   end
                                else if FRIENDLY  then
                                   begin
                                      write('Are you a New User? ');
                                      ANS:=READ_STRING;writeln;
                                      if ANS[1] = 'Y' then
                                         begin
                                           GET_NEW_USER(FN,LN,N);
                                           writeln;
                                           if VERBOSE then write('Updating USER');
                                           write(USRS,N);
                                           close(USRS);
                                           UPDATE_FILES(N);
                                           SEARCHING:=false;
                                           BBON:=true;
                                         end
                                    end
                              end
                           else if FRIENDLY  then
                                   begin
                                      write('Are you a New User? ');
                                      ANS:=READ_STRING;writeln;
                                      if ANS[1] = 'Y' then
                                         begin
                                           GET_NEW_USER(FN,LN,N);
                                           writeln;
                                           if VERBOSE then write('Updating USER');
                                           write(USRS,N);
                                           close(USRS);
                                           UPDATE_FILES(N);
                                           SEARCHING:=false;
                                           BBON:=true;
                                         end
                                    end
                         end
                      else
                         begin
                            if (length(FN)>0) and (length(LN)>0) then
                               begin
                                  SEARCHING:=false;
                                  with N do
                                     begin
                                         FPOS:=-1;
                                         FN:='SYSOP';
                                         LN:='';
                                         AD:='HOST BASE';
                                         SPECIAL:=true;
                                     end;
                                  UPDATE_FILES(N);
                                  BBON:=true;
                               end
                         end
                   end
                 else
                    begin
                      SEARCHING:=false;
                      BBON:=false;
                      QUICK_LOGON:=true;
                      BACK_TO_CPM:=true;
                    end;
           end; {While}
           if SEARCHING then BBON:=false;
           if BBON then CHECK_FOR_MESSAGES;
       end;{LOGON}
