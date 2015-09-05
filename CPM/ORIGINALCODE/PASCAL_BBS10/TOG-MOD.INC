    procedure TOGGLE_X;
       begin
              if XPERT then
                   DISPLAY:=COMM_LINE
              else
                  DISPLAY:=COMM_LINE+PROMPT;
       end; {TOGGLE_X}
