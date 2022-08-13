"""
Generates packet or reconstructed stream output with ANSI color codes.

Based on output module originally written by amm
"""

from datetime import datetime
import json
from dshell.output.output import Output
import dshell.core
import dshell.util


class JsonDataOutput(Output):
    _DESCRIPTION = "Reconstructed output to json"

    _DEFAULT_FORMAT = "%(jsondata)s\n"
    _DEFAULT_DELIM = "\n\n"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hexmode = kwargs.get('hex', False)

    def write(self, *args, **kwargs):
        rawdata = []
        for arg in args:
            if type(arg) == dshell.core.Blob:
                if arg.data:
                    rawdata.append((arg.data, arg.direction))
            elif type(arg) == dshell.core.Connection:
                for blob in arg.blobs:
                    if blob.data:
                        rawdata.append((blob.data, blob.direction))
            elif type(arg) == dshell.core.Packet:
                rawdata.append(
                    (arg.pkt.body_bytes, kwargs.get('direction', '--')))
            elif type(arg) == tuple:
                rawdata.append(arg)
            else:
                rawdata.append((arg, kwargs.get('direction', '--')))

        # Clean up the rawdata into something more presentable
        for k, v in enumerate(rawdata):
            if self.hexmode:
                v[0] = dshell.util.cleanup_func(v[0])
            rawdata[k] = (v[0], v[1])

        # Convert the raw data strings into color-coded output
        data = {
            **kwargs,
            "cs": [],
            "sc": [],
            "--": [],
        }
        for arg in rawdata:
            data[arg[1]].append(arg[0])

        super().write(jsondata=json.dumps(data, ensure_ascii=False, default=self.json_default))

    def json_default(self, obj):
        """
        JSON serializer for objects not serializable by default json code
        https://stackoverflow.com/a/22238613
        """
        if isinstance(obj, datetime):
            serial = obj.strftime(self.timeformat)
            return serial
        if isinstance(obj, bytes):
            serial = obj.decode("latin-1")
            return serial
        if isinstance(obj, (dshell.core.Connection, dshell.core.Blob, dshell.core.Packet)):
            serial = obj.info()
            return serial
        raise TypeError("Type not serializable ({})".format(str(type(obj))))


obj = JsonDataOutput
