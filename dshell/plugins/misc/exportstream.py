"""
Generates color-coded Screen/HTML output similar to Wireshark Follow Stream
"""

from os import makedirs
import dshell.core
from dshell.output.exportout import ExportOutput


class DshellPlugin(dshell.core.ConnectionPlugin):
    out: ExportOutput

    def __init__(self):
        super().__init__(
            name="ExportStream",
            author="yoshino-s",
            description="Export output similar to Wireshark Follow Stream. Empty connections will be skipped.",
            output=ExportOutput(label=__name__),
            optiondict={
                "outdir": {
                    "type": str,
                    "help": "Write to DIR instead of stdout",
                    "metavar": "DIR",
                }
            }
        )
        self.outdir = None  # Filled in with constructor

    def premodule(self):
        self.out.dir = self.outdir
        if self.outdir:
            makedirs(self.outdir, exist_ok=True)

    def connection_handler(self, conn):
        if (conn.clientbytes + conn.serverbytes > 0):
            self.write(conn, **conn.info())
            return conn

    def export(self):
        return self.out.data


if __name__ == "__main__":
    print(DshellPlugin())
