{                   **** PasBBS ver 1.3 ****
                (Pascal Bulletin Board Service)
                      by Bryan A. Nace
          (C) Copyright Westinghouse Electric Corp 1984
                       all rights reserved

 7/31/84   ver 1.3
     Added a configuration boolean and procedure in LOFF-MOD.INC to allow passwording
     of CPM access with a defined password set as TRD_PASS. This will allow operators
     to grant a FRIENDLY Bulletin Board but a restricted CPM. Also corrected error in
     code  of LOG-MOD.INC that null first and last names in the FRIENDLY  mode  would
     allowed  access to system. I have included the MENURBBS that we are currently using
     to explain the 'N' function. Actually, this is a phone list which contains phone
     numbers  that the SYSOP may want to display remotely.  Just use Wordstar or some
     other  editor  to  collect the list and store it on the DISK and  USR  that  you
     declare  in the configuration section.  Choosing 'N' from the command line  will
     display the list via the FILE_READER procedure.           - B.NACE

     This is a structured version of the popular public domain program RBBS31.BAS.
It is modularized and structured to include the equivalent of the EQUate statements
of BYE,MODEM,XMODEM etc. to provide the user with the ability to quickly configure
PasBBS to their own needs. PasBBS is intended as Public Domain Software. The Pascal
version was created to clean up the numerous GOSUBs, GO TOs, ambiguous identifiers,
etc. of the BASIC version. Also I wanted a program that could be  easily modified
as the needs of our CP/M telecommunications changed.
     Features included in this program include
      1). Structured modular construction of procedures/functions.
      2). Compiles to about half the size of a Bascom compiled RBBS.
      3). Ability to define file storage drive and user in area inaccessable
          to remote user by use of the DISK & USR feature.
      4). Random file access for all files except MESSAGE_FILE and
          LAST_CALLER_FILER files.
      5). Convienient configuration into a non-FRIENDLY mode in which the SYSOP
          must grant prior access to the system via 'A'dd_names function rather
          than automatic access via 'Are you a new user?' interagation.
      6). Ability to select a VERBOSE or not VERBOSE mode in which system statistics
          and file updates are displayed on the screen.
      7). Pauses in display of Bulletins by insertion of a '~' character within
          the text of Bulletins during entry in Wordstar.
      8). Ability to be expanded or shortened by either the addition of more
          INClude files or the deletion of existing ones.

         The first section of code contains utilities that may be accessed from
    any module. These general purpose utilities must remain in the program file
    in the order that they appear.
          To add additional procedures/functions to the program:
                 1) Define procedure/function in Turbo. Save the procedure
                    as xxxx-MOD.INC, where 'xxxx' is a unique filename.
                 2) Add the desired command signal to the set definition
                    COMMAND below.
                 3) Add the command signal character to the case statement
                    at the end of this section.
                 4) Add the statement ($I xxxx-MOD.INC) in the list of include
                    files within this section.
    The modularity of PasBBS is structured such that any additions/deletions to
    the commands should be inserted as self standing INClude files. Further more
    the convention has been used that:

                 1) Identifiers are in Uppercase.
                 2) Keywords are in Lowercase.

         The modules included in this version along with their function and case
     input signal are listed below:

          INCLUDE FILE             FUNCTION               COMMAND SIGNAL
      ======================================================================
         SCN-MOD.INC      Special SYSOP function to           'L'
                          Scan USER file for num. of
                          logons.
         ADD-MOD.INC      Special SYSOP function to           'A'
                          add users if not FRIENDLY
                          configuration.
         NPAS-MOD.INC     Change user PASSWORDS.              'P'
         TOG-MOD.INC      Toggle expert mode.                 'X'
         CALR-MOD.INC     Lists callers in order              'U'
         SYS-MOD.INC      Special SYSOP function to           'Z'
                          retrieve SYSOP messages.
         REC-MOD.INC      Receive messages.                   'R'
         KILL-MOD.INC     Kill messages.                      'K'
         SUM-MOD.INC      Scan messages.                      'S'
         LOG-MOD.INC      Logon to system                    executed on entry
         MES-MOD.INC      Enters messages either             'E'
                          SYSOP or users messages.
         LOFF-MOD.INC     Exits system                       executed on exit

          ***** TO COMPILE YOUR PasBBS.COM *****

          From the Command line of Turbo-Pascal type "O" for compiler Options,
    then choose "C" for Command file. Exit from compiler options via "Q" for Quit.
    This should return you to the main command line of Turbo. Choose "M" to specify
    a Main file which is PASBBS.PAS. After entering the Main filename, type "C"
    to compile. The rest is automatic and a COM file of PasBBS configured to your
    needs will be produced.


          Any changes in this program should be forwarded to:


                       Bryan A. Nace
                       51 Constitution Ave.
                       Box 303
                       New Freedom, Pa.

          or to the BHEC RCPM (301) 661-2175

                                          Good Luck,
                                          Bryan Nace
}
Program PasBBS;

const LINE_LEN = 64;
      MSG_LEN = 20;
      PASS_LEN = 6;
      FNAME_LEN = 10;
      LNAME_LEN = 10;
      TO_AND_FROM = 21;
      ADD_LEN = 25;
      SUB_LEN = 25;
      DELAY_TIME = 2000;                        {Approx 2 sec delay for screen switches}
      MAX_TRY = 3;                              {Maximum no of logon attempts allowed  }
      PAGE_BOTTOM = 23;                         {row of bottom of video display        }
      SELDISK = 14;                             { CP/M disk select function number     }
      SELUSER = 32;                             { CP/M user select function number     }
      JUMP = $C3;                               { 8080 JUMP instruction                }
      CALL = $CD;                               { 8080 CALL instruction                }
      BOOT = $0000;                             { address of warmboot vector           }
      DISK_ADDR = $0004;                        { address of CP/M drive,user vector    }
      RFLG = $5D;                               { address gets set to ' ' on WBOOT     }
      RTNOKFLG = $5B;                           { address gets set to 'x' on LOGON     }
      FRIENDLY = false;                         {true allows remote new user entry     }
      VERBOSE = false;                          { true displays file handling          }
      NOWEL = false;                            { false displays welcome message       }
      NOBUL = true;                             {false displays bulletin on logon      }
      CPM_PASS = false;                         { true passwords CPM entry             }
      DISK = 0;                                 {default disk drive for file storage 0=A,1=B,...  }
      USR = 15;                                 {default user area for file storage  0=0,1=1,...  }
      MESSAGE_FILE = 'MESSGS';                  { can choose to define filenames here  }
      SUMMARY_FILE = 'SUMMARY';
      USER_FILE = 'USERS';
      STATISTIC_FILE = 'STATS';
      LAST_CALLER_FILE = 'LASTCALR';
      CALLER_FILE = 'CALLERS ';
      TRD_PASS = 'ACCESS' ;                     { CPM access password                  }
      FST_PASS = 'CPM';                         { password for direct CP/M entry       }
      SND_PAS = 'NACE';                         { sysop password                       }
      DEF_PASS = 'DEFLT';                       { default password for messages        }
      VERSION = 'PasBBS version 1.3  (7/31/84)   By Bryan A. Nace';
      COMM_LINE = 'Command: ';
      PROMPT = 'B,E,R,S,K,G,W,N,C,U,T,X,P (or ? if not known): ';
      MG_PROMPT = 'Select: (H)eader, (L)ist, (E)dit, (A)bort, (C)ontinue, (S)ave: ';
      CONTINUE = '[ press RETURN key to continue ]';

   type  LINE= string[LINE_LEN];
         PWORD=string[PASS_LEN];
         SUBJECT = string[SUB_LEN];
         USER = record
                FN:STRING[FNAME_LEN];
                LN:STRING[LNAME_LEN];
                AD:string[ADD_LEN];
                PW:string[PASS_LEN];
                LG:smallint;
                FPOS:smallint;
                end;
          CMD = set of '?'..'Z';
          CALLER  = record
                    FN:string[FNAME_LEN];
                    LN:string[LNAME_LEN];
                    AD:string[ADD_LEN];
                    end;
          STATISTICS = record
                       US:smallint;
                       MNO:smallint;
                       AC:smallint;
                       end;
          MESSAGE = record
                    SZ:smallint;
                    N:smallint;
                    TXT:array[1..MSG_LEN] of LINE;
                    end;
          SUMMARY = record
                    FILE_POS:smallint;
                    T:string[TO_AND_FROM];
                    F:string[TO_AND_FROM];
                    DT:string[8];
                    SUB: string[SUB_LEN];
                    PW:string[PASS_LEN];
                    ACT:boolean;
                    end;
    const COMMAND :CMD  =   ['B','E','R','S','K','G','W','N','C','U','T','X','P',
                         '?','L','Z','A'];
   var LCALR,MSG:text;
       UDATA:STATISTICS;
       USRS: file of USER;
       CALR: file of CALLER;
       STAT: file of STATISTICS;
       SUMRY: file of SUMMARY;
       ANS,ERSE,DISPLAY,FN,LN:LINE;
       UP_CASE,OK_TO_LIST,PASS_CK,BACK_TO_CPM,BELL,
       QUICK_LOGON,BBON,XPERT,HANG_UP,SPECIAL,SYSOP_MESSAGE:boolean;
       BASE: byte absolute BOOT;
       DU:byte absolute DISK_ADDR;
       RET_FLAG: byte ABSOLUTE RFLG;
       RETNOK_FLAG: byte ABSOLUTE RTNOKFLG;
       RET_STATUS,RETNOK_STATUS:byte;
       TRY,LOGONS:smallint;

   {  ***** SYSTEM UTILITY FUNCTIONS/PROCEDURES *****         }
   {        Any procedure or function that is accessable
      from several modeules within the program should be
      located within this section.                            }

   function EXIST(FILENAME:LINE):boolean;
        var FIL:file;
        begin
           assign(FIL,FILENAME);
           {$I-}
           reset(FIL);
           {I+}
           if IOresult<>0 then
                EXIST:=false
            else
                EXIST:=true;
        end;
   procedure GET_NAMES(L:LINE;var FN,LN:LINE);
      var I:smallint;
      begin
          I:=pos(' ',L);
          FN:=copy(L,1,I-1);
          LN:=copy(L,I+1,length(L)-I);
      end;{GET_NAMES}
   procedure INIT;
       begin
           BASE:=CALL;
           RET_STATUS:=RET_FLAG;
           RETNOK_STATUS:=RETNOK_FLAG;
           RET_FLAG:= $50;
           RETNOK_FLAG:=120;
           QUICK_LOGON:=false;
           BACK_TO_CPM:=false;
           if (RET_STATUS=ord('P')) and (RETNOK_STATUS=ord('x')) then
               begin
                  assign(LCALR,LAST_CALLER_FILE);reset(LCALR);
                  readln(LCALR,LOGONS,ANS);
                  close(LCALR);
                  GET_NAMES(ANS,FN,LN);
                  writeln;writeln('Welcome back ',FN);
                  DELAY(DELAY_TIME);
                  QUICK_LOGON:=true;
                  BACK_TO_CPM:=true;
               end;
           UP_CASE:=true;
           PASS_CK:=false;
           XPERT  :=false;
           BBON   :=true;
           SPECIAL:=false;
           BELL   :=true;
           HANG_UP:=false;
           SYSOP_MESSAGE:=false;
           ERSE:= chr(8) + ' ' + chr(8);
           DISPLAY:=COMM_LINE+PROMPT;
           TRY:=0;
           assign(STAT,STATISTIC_FILE);
           if EXIST(STATISTIC_FILE) then
              begin
                 RESET(STAT);
                 read(STAT,UDATA)
              end
           else
              begin
                 REWRITE(STAT);
                 UDATA.US:=0;UDATA.MNO:=0;UDATA.AC:=0;
                 write(STAT,UDATA);
              end;
           close(STAT);
        end;{INIT}
    procedure FILE_READER(F:char);
         var CH:char;
             FILENAME:textfile;
         begin
           case F of
                'B':begin assigntext(FILENAME,'BULLETIN');reset(FILENAME) end;
                'W':begin assigntext(FILENAME,'WELCOME');reset(FILENAME) end;
                '?':begin assigntext(FILENAME,'MENURBBS');reset(FILENAME) end;
                'N':begin assigntext(FILENAME,'FB111PER');reset(FILENAME) end;
            end; {of case}
           clrscr;
           while NOT EOF(FILENAME) do
              begin
                  read(FILENAME,CH);
                  if CH='~' then
                    begin
                         write(CONTINUE);
                         read(KBD,CH);
                         CH:=' ';
delLine;
write(ERSE);
                     end;
                   write(CH);
               end;
           writeln(CH);
         end;
     function READ_STRING:LINE;
         var S:LINE;
             I:smallint;
         begin
             if PASS_CK then
                read(KBD,S)
             else
                read(S);
             if UP_CASE then
                 for I:=1 to length(S) do
                    S[I]:=upcase(S[I]);
             read_STRING:=S;
         end; {READ_STRING}
     procedure GET_PASS(var S:PWORD);
        label 8;
        var CH:char;
            S1,S2:LINE;
        begin
             PASS_CK:=true;
             writeln;
8   :        write('Enter up to ',PASS_LEN,' characters for your PASSWORD: ');
             S1:=READ_STRING;
             writeln;
             write('Now,enter your PASSWORD a second time: ');
             S2:=READ_STRING;
             if S1<>S2 then
                 begin
                     writeln;
                     writeln('Not Identical try again');writeln;
                     goto 8
                 end
             else
                 S:=S1;
            writeln;writeln;
            writeln('Remember this PASSWORD to use for LOGONS ');
            PASS_CK:=false;
        end;                   {GET_PASS}
     procedure LIST_MESSAGE(S:SUMMARY;M:MESSAGE);
       var PW:PWORD;
       procedure LIST_BODY(M:MESSAGE);
            var I:smallint;
               AN:LINE;
            begin
               writeln;writeln;
               for I:=1 to M.SZ do
                  begin
                     if I = 13  then
                       begin
                         write(CONTINUE);
                         AN:=READ_STRING;
                         delLine;
                       end;
                     writeln(I:3,'> ',M.TXT[I]);
                  end;
            end;{LIST_BODY}
       begin
         if (PASS_CK) and(S.PW<>DEF_PASS) and  (S.PW<>'*') then
           begin
              write('Enter PASSWORD for personal Message ');
              PW:=READ_STRING;writeln;
              if PW = S.PW then OK_TO_LIST := true else OK_TO_LIST :=false
           end
       else
           OK_TO_LIST:=true;
       delay(DELAY_TIME div 2);
       if OK_TO_LIST then
              begin
                  clrscr;
                  writeln('Message #',S.FILE_POS);
                  writeln('To:      ',S.T);
                  writeln('From:    ',S.F);
                  writeln('Subject: ',S.SUB);
                  writeln('Date:    ',S.DT);
                  LIST_BODY(M)
               end
         else
                writeln('You must have PASSWORD to view this message');
     end;

    {  ***** ADD INClude files here ***** }

    {$I SCN-MOD.INC}
    {$I ADD-MOD.INC}
    {$I NPAS-MOD.INC}
    {$I TOG-MOD.INC }
    {$I CALR-MOD.INC}
    {$I SYS-MOD.INC}
    {$I REC-MOD.INC}
    {$I KILL-MOD.INC}
    {$I SUM-MOD.INC}
    {$I LOG-MOD.INC}
    {$I MES-MOD.INC}
    {$I LOFF-MOD.INC}
    begin
        bdos(SELDISK,DISK);bdos(SELUSER,USR);
        INIT;
        if not QUICK_LOGON then
           begin
            if (not NOWEL)  then FILE_READER('W');
            if (not NOBUL)  then FILE_READER('B');
            if (NOBUL) and (NOWEL)  then writeln(chr(26),VERSION);
            LOGON(FN);
            delay(DELAY_TIME);
            while (BBON)  do begin
             TRY:=0;
             if BELL then write(chr(7));
             if BBON then begin clrscr;gotoXY(3,PAGE_BOTTOM);write(ERSE+ERSE,DISPLAY);ANS:=READ_STRING; writeln end;

             {   ***** main command loop *****
                 add additional commands here    }

             if (ANS[1] in COMMAND) and (BBON) then
                 case ANS[1] of
                    'B':FILE_READER('B');
                    'E':ENTER_MESSAGE;
                    'R':RECIEVE_MESSAGE(ANS);
                    'S':SCAN_SUMMARY;
                    'K':KILL_MSG(ANS);
                    'G':begin HANG_UP:=true;BBON:=false end;
                    'N':FILE_READER('N');
                    'W':FILE_READER('W');
                    'C':begin BACK_TO_CPM:=true;BBON:=false end;
                    'U':LIST_CALLERS;
                    'T':BELL:=not BELL;
                    'P':GET_NEW_PASS;
                    '?':FILE_READER('?');
                    'X':begin XPERT:= not XPERT; TOGGLE_X end;
                    'L':if SPECIAL then SCAN_USERS;
                    'Z':GET_SYSOP_MESSAGES;
                    'A':if SPECIAL then ADD_USERS;
                  end
             else
                begin
                     TRY:=TRY+1;
                     if TRY>=MAX_TRY then BBON:=false;
                     writeln;
                     writeln('I don''t understand ',ANS,' ',FN);
                     writeln;
                end;
             end; {WHILE BBON}
           end; {IF NOT QUICK_LOGON}
           LOGOFF(FN);
        end.
