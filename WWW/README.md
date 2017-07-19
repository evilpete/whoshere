# README #

A example HTML page to display whoshere status information


-------

## How do I set it up? ##

Copy [whoshere.html](/WWW/whoshere.html) to your web-server's html directory

Configure whoshere to write it's `status_file` to the same area

Edit [whoshere.html](/WWW/whoshere.html) and edit the line:

```
    <script src="cur-status.json"></script>
```

to reflect the correct server path for the `status_file`

Alternately if the HTTP_PORT option is set to:

```
    http://HOSTNAME:XX/whoshere-status.js
```
where **HOSTNAME** is the server host and **XX** is the value of the `HTTP_PORT` config option

---

![+webpage](/WWW/.screen_shots/Screenshot_44.png)


