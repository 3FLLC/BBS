 procedure GET_NEW_PASS;
        var L:LINE;
            U:USER;
            REC_NO:integer;
        begin
            assign(LCALR,LAST_CALLER_FILE);reset(LCALR);
            read(LCALR,REC_NO,L);
            close(LCALR);
            assign(USRS,USER_FILE);reset(USRS);
            seek(USRS,REC_NO-2);
            read(USRS,U);
            GET_PASS(U.PW);
            seek(USRS,REC_NO-2);
            write(USRS,U);
            close(USRS);
        end; {GET_NEW_PASS}
