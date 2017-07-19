

to run whoshere.py at startup with systemd :

    cp whoshere.service /lib/systemd/system/
    chmod 644  /lib/systemd/system/whoshere.service
    systemctl enable whoshere

also copy config whoshere.ini 
