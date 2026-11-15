"""Kill switch read from outside the process.

An operator stops the agent by creating the kill file (or by having the
platform create it). The agent re-reads the file before every model call and
every tool call, so no new action starts after the file appears.
"""

import os


class AgentKilled(RuntimeError):
    pass


class KillSwitch:
    def __init__(self, path):
        self.path = path

    def is_engaged(self):
        return os.path.exists(self.path)

    def raise_if_engaged(self):
        if self.is_engaged():
            raise AgentKilled("kill switch is engaged; no further actions will run")
