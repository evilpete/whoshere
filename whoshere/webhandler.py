
from __future__ import print_function
#from BaseHTTPServer import BaseHTTPRequestHandler
from http.server import BaseHTTPRequestHandler # , HTTPServer
import select
import time
import json

from .conf import TIME_FMT

# TIME_FMT = "%Y-%m-%d %H:%M:%S"

__all__ = ['webHandler']

# logiing hint: https://stackoverflow.com/questions/20281709/how-do-you-override-basehttprequesthandler-log-message-method-to-log-to-a-file
class webHandler(BaseHTTPRequestHandler):
    """
        Class to handle BaseHTTPServer HTTP requests
    """
    arp_obj = None
    chunked = False
    # _verbose = 0

    def log_message(self, lformat, *args):
        t = time.strftime(TIME_FMT, time.localtime())
        print("{}\t{} {}\t{}".format(t, "HTTPRequest", self.client_address[0], lformat%args))

    def do_HEAD(self):
        if self.path.startswith("/whoshere-status."):
            self.do_stat_responce(justhead=True)
#        elif self.path == "/whoshere.html":
#            self.do_file_serve("/var/www" + "/whoshere.html")

    def do_GET(self):
        if self.path.startswith("/whoshere-status."):
            self.do_stat_responce()
        else:
            self.send_error(404, "File Not Found: {}".format(self.path))

#        elif self.path == "/whoshere.html":
#            self.do_file_serve("/var/www" + "/whoshere.html")

#    def do_file_serve(self, path):
#        try:
#            with open(path, 'r') as f:
#                self.send_response(200)
#                self.send_header('Content-type', 'text/html')
#                self.end_headers()
#                self.wfile.write(f.read())
#        except IOError:
#            self.send_error(404, "File Not Found: {}s".format(self.path))

    def do_stat_responce(self, justhead=False):
        try:
            jdata = ""
            if self.path.endswith(".js"):
                jdata = "jdata = "
                mimetype = 'application/javascript'
            elif self.path.endswith(".json"):
                mimetype = 'application/json'
            else:
                self.send_error(404, "File Not Found: {}".format(self.path))
                return

            data = self.arp_obj.generate_status_list()
            jdata += json.dumps(data, sort_keys=True, indent=2)

            mimetype = 'application/json'
            self.send_response(200)
            self.send_header('Content-type', mimetype)
            self.send_header('Cache-Control', "max-age=30, Private")
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Connection', 'close')
            # if self.chunked
            #    self.send_header('Transfer-Encoding': "chunked")
            self.send_header('Content-Length', len(jdata))
            # self.send_header('Pragma', "no-cache")
            self.end_headers()

            if not justhead:
                # if self.chunked
                #    self.wfile.write('{:X}\r\n{}\r\n'.format((len(jdata), jdata)))
                # else:
                self.wfile.write(jdata)

        except select.error as _se:
            self.send_error(503, 'Service Unavailable')

#    def log_message(self, format, *args):
#        sys.stderr.write("%s - - [%s] %s\n" %
#            (self.client_address[0],
#            self.log_date_time_string(),


#
# Do nothing
# (syntax check)
#
if __name__ == "__main__":
    import __main__
    print(__main__.__file__)

    print("syntax ok")
    exit(0)
