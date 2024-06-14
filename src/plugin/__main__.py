# --------------------------------------------------------------------------- #
from client.requests.base import typerize
from plugin import PluginCommands


def main():
    cmd = typerize(PluginCommands)
    cmd()


if __name__ == "__main__":
    main()
